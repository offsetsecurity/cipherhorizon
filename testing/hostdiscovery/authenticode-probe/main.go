//go:build windows

// authenticode-probe is an INVESTIGATION tool, not part of the collector and not
// shipped. It answers one question before any Authenticode evidence is added to the
// collector: can WinVerifyTrust verify a file's embedded signature OFFLINE, with no
// network activity, and still give a useful answer?
//
// It verifies each file twice, once in the mode a collector would use and once in
// the default, network-capable mode:
//
//	offline: WTD_REVOKE_NONE, WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
//	online:  WTD_REVOKE_WHOLECHAIN (revocation checking of the whole chain, allowed to fetch)
//
// and, around each call, looks for the two visible side effects of a network fetch:
// TCP connections owned by this process (sampled every millisecond) and new or
// updated files in the CryptoAPI URL cache (%USERPROFILE%\AppData\LocalLow\Microsoft\
// CryptnetUrlCache), which is where fetched CRLs and OCSP responses are stored.
//
// Neither is proof of absence (a connection shorter than a millisecond can be missed;
// a fetch that is not cached leaves no file), so the report says "not observed", never
// "did not happen". The verdict on shipping the sensor also rests on the design: the
// offline flags are documented by Microsoft as forbidding URL retrieval.
//
// Usage: authenticode-probe [-json] file...
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var results = map[uint32]string{
	0x00000000: "valid",
	0x800B0100: "TRUST_E_NOSIGNATURE (no embedded signature)",
	0x800B0101: "CERT_E_EXPIRED",
	0x800B0109: "CERT_E_UNTRUSTEDROOT",
	0x800B010A: "CERT_E_CHAINING",
	0x800B0004: "TRUST_E_SUBJECT_NOT_TRUSTED",
	0x800B0111: "TRUST_E_EXPLICIT_DISTRUST",
	0x80096010: "TRUST_E_BAD_DIGEST (file changed after signing)",
	0x80096005: "TRUST_E_SUBJECT_FORM_UNKNOWN",
	0x80092003: "CRYPT_E_FILE_ERROR",
	0x80092026: "CRYPT_E_SECURITY_SETTINGS",
	0x80096004: "TRUST_E_CERT_SIGNATURE",
	0x800B0003: "TRUST_E_SUBJECT_FORM_UNKNOWN",
	0x80092013: "CRYPT_E_REVOCATION_OFFLINE",
	0x800B010C: "CERT_E_REVOKED",
	0x80096002: "TRUST_E_FAIL",
	0x80093103: "CRYPT_E_ASN1_CORRUPT (signature data corrupt)",
}

type mode struct {
	name       string
	revocation uint32
	flags      uint32
}

var modes = []mode{
	{"offline", windows.WTD_REVOKE_NONE, windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL},
	{"online", windows.WTD_REVOKE_WHOLECHAIN, 0},
}

// Observation is one verification of one file in one mode.
type Observation struct {
	File        string   `json:"file"`
	Mode        string   `json:"mode"`
	Code        string   `json:"code"`
	Meaning     string   `json:"meaning"`
	Millis      int64    `json:"millis"`
	Connections []string `json:"tcpConnectionsSeen"`
	CacheChange int      `json:"urlCacheFilesNewOrChanged"`
}

func verify(path string, m mode) uint32 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0x80092003
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	d := &windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: m.revocation, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi), //nolint:gosec // the API takes the file info by pointer
		StateAction:                     windows.WTD_STATEACTION_VERIFY, ProvFlags: m.flags,
	}
	action := windows.WINTRUST_ACTION_GENERIC_VERIFY_V2
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &action, d)
	code := uint32(0)
	if err != nil {
		var e syscall.Errno
		if errors.As(err, &e) && uint64(e) <= 0xffffffff {
			code = uint32(e)
		} else {
			code = 0x80096002
		}
	}
	d.StateAction = windows.WTD_STATEACTION_CLOSE // release the provider state
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &action, d)
	runtimeKeepAlive(fi, p)
	return code
}

//go:noinline
func runtimeKeepAlive(...any) {}

var (
	iphlpapi     = windows.NewLazySystemDLL("iphlpapi.dll")
	getTCPTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	tcpTableOwn  = uintptr(5) // TCP_TABLE_OWNER_PID_ALL
	afInet       = uintptr(2)
	ourPID       = uint32(os.Getpid())
	cacheSubdirs = []string{"MetaData", "Content"}
)

// tcpFor returns the remote endpoints of TCP connections this process owns right now.
func tcpFor() []string {
	var size uint32
	_, _, _ = getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwn, 0) //nolint:gosec // Windows API call
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	if r, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwn, 0); r != 0 { //nolint:gosec // Windows API call
		return nil
	}
	n := binary.LittleEndian.Uint32(buf)
	var out []string
	for i := uint32(0); i < n; i++ {
		off := 4 + i*24
		if int(off)+24 > len(buf) {
			break
		}
		raw := buf[off : off+24]
		remote, owner := raw[8:12], binary.LittleEndian.Uint32(raw[20:])
		if owner != ourPID || binary.LittleEndian.Uint32(remote) == 0 {
			continue
		}
		port := int(raw[12])<<8 | int(raw[13]) // network byte order
		out = append(out, fmt.Sprintf("%s:%d", net.IP(remote).String(), port))
	}
	return out
}

func urlCacheState() map[string]time.Time {
	base := filepath.Join(os.Getenv("USERPROFILE"), "AppData", "LocalLow", "Microsoft", "CryptnetUrlCache")
	state := map[string]time.Time{}
	for _, sub := range cacheSubdirs {
		ents, _ := os.ReadDir(filepath.Join(base, sub))
		for _, e := range ents {
			if fi, err := e.Info(); err == nil {
				state[sub+"/"+e.Name()] = fi.ModTime()
			}
		}
	}
	return state
}

func changed(before, after map[string]time.Time) int {
	n := 0
	for k, t := range after {
		if b, ok := before[k]; !ok || !b.Equal(t) {
			n++
		}
	}
	return n
}

func observe(path string, m mode) Observation {
	before := urlCacheState()
	seen := map[string]bool{}
	var mu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, c := range tcpFor() {
				mu.Lock()
				seen[c] = true
				mu.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	start := time.Now()
	code := verify(path, m)
	elapsed := time.Since(start)
	close(stop)
	<-done

	var conns []string
	for c := range seen {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	meaning := results[code]
	if meaning == "" {
		meaning = "(unmapped)"
	}
	return Observation{File: path, Mode: m.name, Code: fmt.Sprintf("0x%08X", code), Meaning: meaning,
		Millis: elapsed.Milliseconds(), Connections: conns, CacheChange: changed(before, urlCacheState())}
}

func main() {
	asJSON := flag.Bool("json", false, "print JSON")
	flag.Parse()
	var all []Observation
	for _, f := range flag.Args() {
		for _, m := range modes {
			all = append(all, observe(f, m))
		}
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(all)
		return
	}
	for _, o := range all {
		fmt.Printf("%-8s %s  %-46s %5d ms  tcp=%v  urlCacheChanged=%d   %s\n", o.Mode, o.Code, o.Meaning, o.Millis, o.Connections, o.CacheChange, o.File)
	}
}
