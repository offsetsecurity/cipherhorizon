package machinefacts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/knowledge"
	"github.com/example/cipherhorizon/internal/signatures"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func selfSigned(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func components(bom *cdx.BOM) map[string]cdx.Component {
	out := map[string]cdx.Component{}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			out[c.Name] = c
		}
	}
	return out
}

func metaProps(bom *cdx.BOM) string {
	var b strings.Builder
	if bom.Metadata != nil && bom.Metadata.Properties != nil {
		for _, p := range *bom.Metadata.Properties {
			b.WriteString(p.Name + "=" + p.Value + "\n")
		}
	}
	return b.String()
}

func TestLinuxFactsBecomeTheCollectorsCBOM(t *testing.T) {
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t, "web.example")})
	keyFile := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	facts := strings.Join([]string{
		"cipherhorizon-machine-facts\t1",
		"script\tlinux-sh\t1.0.0",
		"host\tname\tweb-01",
		"host\tos\tlinux",
		"host\tprivilege\tadmin",
		"os-release\t" + b64([]byte("ID=debian\nVERSION_ID=13\n")),
		"package-manager\tdpkg",
		"package\tdpkg\topenssl\t3.5.1-1\tamd64",
		"package\tdpkg\tlibgcrypt20\t1.11.0-7\tamd64",
		"package\trpm\tgnutls\t3.8.3-4.el9\tx86_64",
		"package\tdpkg\tbash\t5.2-1\tamd64", // not crypto: ignored by the knowledge base
		"cert-file\t/etc/nginx/ssl/web.crt\t" + b64(leaf),
		"cert-file\t/etc/nginx/ssl/web.pem\t" + b64(append(append([]byte{}, leaf...), keyFile...)), // refused: holds a key
		"cert-file\t/etc/../../etc/x.crt\t" + b64(leaf),                                            // a path that climbs: cleaned, then kept under etc/
		"mystery\tline",
	}, "\n")
	f, err := Parse([]byte(facts))
	if err != nil {
		t.Fatal(err)
	}
	if f.Dropped != 2 || len(f.CertFiles) != 2 || f.CertFiles[1].Path != "etc/x.crt" {
		t.Fatalf("parse: dropped %d, cert files %+v", f.Dropped, f.CertFiles)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	cs := components(bom)
	for _, want := range []string{"openssl", "libgcrypt20", "gnutls", "ML-KEM-768", "RSA"} {
		if _, ok := cs[want]; !ok {
			t.Errorf("component %q missing; have %d components", want, len(cs))
		}
	}
	if _, ok := cs["bash"]; ok {
		t.Error("a package the knowledge base does not know is not inventoried")
	}
	if g := cs["gnutls"]; g.PackageURL == "" || !strings.HasPrefix(g.PackageURL, "pkg:rpm/debian/gnutls") {
		t.Errorf("an rpm package carries an rpm purl: %q", g.PackageURL)
	}
	var sawCert bool
	for _, c := range cs {
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate && strings.Contains(c.Name, "web.example") {
			sawCert = true
		}
	}
	if !sawCert {
		t.Error("the certificate file is in the CBOM")
	}
	props := metaProps(bom)
	for _, want := range []string{"cipherhorizon:privilege-tier=admin", "cipherhorizon:host-os=linux debian 13", "collected-by=inventory script linux-sh 1.0.0", "2 entries in the facts file were refused"} {
		if !strings.Contains(props, want) {
			t.Errorf("metadata lacks %q:\n%s", want, props)
		}
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name != "web-01" {
		t.Error("the host is the CBOM's subject")
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(bom); err != nil || bytes.Contains(buf.Bytes(), []byte("PRIVATE KEY")) {
		t.Errorf("no key material may reach the CBOM (err %v)", err)
	}
}

func TestWindowsFactsUseTheCertificateStoreSensorOnly(t *testing.T) {
	der := selfSigned(t, "intranet.example")
	facts := "cipherhorizon-machine-facts\t1\nhost\tname\tWEB-02\nhost\tos\twindows\nhost\tos-version\tMicrosoft Windows Server 2022 10.0.20348\nhost\tprivilege\tadmin\n" +
		"store-cert\tLocalMachine\tMy\tyes\t" + b64(der) + "\n"
	f, err := Parse([]byte("\xef\xbb\xbf" + facts)) // a byte-order mark is tolerated
	if err != nil {
		t.Fatal(err)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	props := metaProps(bom)
	if !strings.Contains(props, "host-os=windows Microsoft Windows Server 2022 10.0.20348") {
		t.Errorf("the OS is the uploaded machine's, never the server's:\n%s", props)
	}
	if strings.Contains(props, "sensor=windows-cng") || strings.Contains(props, "sensor=pe-files") {
		t.Error("only the fact-backed certificate sensor runs; nothing reads the server")
	}
	var sawCert bool
	for _, c := range components(bom) {
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			sawCert = true
		}
	}
	if !sawCert {
		t.Error("the store certificate is in the CBOM")
	}
}

func TestParseRefusesWhatIsNotAFactsFile(t *testing.T) {
	for name, in := range map[string]string{
		"json":     `{"bomFormat":"CycloneDX"}`,
		"version3": "cipherhorizon-machine-facts\t3\nhost\tos\tlinux\n",
		"no os":    "cipherhorizon-machine-facts\t1\nhost\tname\tx\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if IsFacts([]byte(`{"a":1}`)) || !IsFacts([]byte("cipherhorizon-machine-facts\t1\n")) {
		t.Error("IsFacts")
	}
}

// The package signature's loose filter must let through every package name the knowledge base
// recognises, or the server would never see it.
func TestScriptPackageFilterCoversTheKnowledgeBase(t *testing.T) {
	sig, ok := signatures.MustLoad().ByID("linux.packages")
	if !ok {
		t.Fatal("no linux.packages signature")
	}
	filter := regexp.MustCompile(sig.Params["match"])
	samples := []string{"openssl", "openssl-libs", "libcrypto3", "libssl3t64", "gnupg", "gpgv", "libgcrypt20", "libgcrypt", "libgnutls30t64", "gnutls",
		"libnettle8t64", "libhogweed6", "nettle", "libsodium23", "libsodium", "libnss3", "nss", "libmbedtls14", "libwolfssl42", "libbotan-2-19",
		"libssh-4", "libssh2-1t64", "openssh-server", "openssh-clients", "openssh", "libk5crypto3", "libkrb5-3", "krb5-libs", "libcrypt1",
		"libcryptsetup12", "python3-cryptography"}
	for _, n := range samples {
		if knowledge.RecognizePackage(n) == nil {
			t.Errorf("sample %q is not a known package; update the samples", n)
		}
		if !filter.MatchString(n) {
			t.Errorf("the script filter drops %q, which the knowledge base knows", n)
		}
	}
	for _, s := range Scripts() {
		if len(s.SHA256) != 64 || s.Size == 0 || s.Run == "" {
			t.Errorf("script %+v", s)
		}
	}
}

// On a Linux machine with dpkg (the CI runners), the real script runs and its output
// converts: the script and the parser agree on the format.
func TestShellScriptOnThisMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the shell script is for Linux")
	}
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("no dpkg on this machine")
	}
	out := filepath.Join(t.TempDir(), "facts.txt")
	script := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(script, Scripts()[1].Body(), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("sh", script, out).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) == 0 || f.OS != "linux" || len(f.OSRelease) == 0 {
		t.Fatalf("facts: %d packages, os %q", len(f.Packages), f.OS)
	}
	if _, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"}); err != nil {
		t.Fatal(err)
	}
}

// Version 2 facts: library files go through the knowledge base, configuration becomes
// components, an unknown signature is still recorded, and every signature's coverage is kept.
func TestSignatureFactsBecomeComponents(t *testing.T) {
	facts := strings.Join([]string{
		"cipherhorizon-machine-facts	2",
		"script	windows-powershell	2.0.0",
		"host	name	WIN-01",
		"host	os	windows",
		"host	os-version	Microsoft Windows Server 2022",
		"host	privilege	admin",
		"signatures	2026.10.04",
		`fact	win.crypto-libraries	file	C:\Program Files\App\libcrypto-3-x64.dll	5805212	abc123	3.5.7	The OpenSSL Toolkit`,
		"ran	win.crypto-libraries	1",
		`fact	win.schannel.protocols	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server	Enabled	0`,
		`fact	win.schannel.suite-order	registry	HKEY_LOCAL_MACHINE\SYSTEM\x\00010002	Functions	TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
		`fact	win.ssh.server-config	line	C:\ProgramData\ssh\sshd_config	KexAlgorithms mlkem768x25519-sha256,curve25519-sha256`,
		`fact	win.ssh.host-keys	line	C:\ProgramData\ssh\ssh_host_ed25519_key.pub	ssh-ed25519 AAAAC3Nza host`,
		"fact	win.programs	program	PuTTY release 0.85	0.85.0.0	Simon Tatham",
		`fact	win.dotnet.tls	registry	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319	SchUseStrongCrypto	1`,
		`fact	win.future.thing	registry	HKEY_LOCAL_MACHINE\SOFTWARE\X	Y	1`,
		`fact	win.programs	line	C:\x	-----BEGIN PRIVATE KEY-----`,
		"skip	win.schannel.suite-policy	not present",
		"ran	win.schannel.suite-policy	0",
	}, "\n")
	f, err := Parse([]byte(facts))
	if err != nil {
		t.Fatal(err)
	}
	if f.Dropped != 1 || len(f.Items) != 8 || f.SignatureDB != "2026.10.04" {
		t.Fatalf("parse: dropped %d, %d items, db %q", f.Dropped, len(f.Items), f.SignatureDB)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cs := components(bom)
	for _, want := range []string{"libcrypto-3-x64.dll", "ML-KEM-768", "Windows Schannel (TLS)", "SSH server (OpenSSH)", "X25519MLKEM768", "X25519", "Ed25519", "SSH host key (ssh-ed25519)", "PuTTY release 0.85"} {
		if _, ok := cs[want]; !ok {
			names := []string{}
			for n := range cs {
				names = append(names, n)
			}
			t.Errorf("component %q missing; have %v", want, names)
		}
	}
	sch := cs["Windows Schannel (TLS)"]
	if sch.CryptoProperties.ProtocolProperties.CipherSuites == nil || len(*sch.CryptoProperties.ProtocolProperties.CipherSuites) != 2 {
		t.Error("the configured suite order is on the Schannel component")
	}
	var schProps []string
	for _, p := range *sch.Properties {
		schProps = append(schProps, p.Value)
	}
	if !strings.Contains(strings.Join(schProps, "|"), "TLS 1.0 (server): disabled") {
		t.Errorf("Schannel properties: %v", schProps)
	}
	props := metaProps(bom)
	for _, want := range []string{"observed-config=.NET Framework TLS settings", "observed-config=win.future.thing", "sensor=win.crypto-libraries status=complete",
		"sensor=win.schannel.suite-policy status=complete scope=Cipher suite order set by Group Policy (Schannel): not present", "signature-db=2026.10.04"} {
		if !strings.Contains(props, want) {
			t.Errorf("metadata lacks %q:\n%s", want, props)
		}
	}
	// The post-quantum verdicts reach the configured algorithms too.
	for _, c := range *bom.Components {
		if c.Name == "X25519MLKEM768" {
			var st string
			for _, p := range *c.Properties {
				if p.Name == "cipherhorizon:pqc:status" {
					st = p.Value
				}
			}
			if st != "quantum-safe" {
				t.Errorf("X25519MLKEM768 status %q", st)
			}
		}
	}
}

// The engines carry no signature of their own; the served scripts carry exactly their
// platform's, so adding a signature changes no engine (PRD-006 R-M3).
func TestServedEnginesCarryTheirPlatformsSignatures(t *testing.T) {
	db := signatures.MustLoad()
	for _, s := range Scripts() {
		engine, err := Engine(s.Name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(engine), "\nsig\t") || !strings.Contains(string(engine), markBegin) {
			t.Errorf("%s: the engine in the repository must hold markers and no signatures", s.Name)
		}
		platform := "linux"
		if strings.HasSuffix(s.Name, ".ps1") {
			platform = "windows"
		}
		body := string(s.Body())
		for _, sig := range db.Signatures {
			has := strings.Contains(body, "sig\t"+sig.ID+"\t")
			if has != (sig.Platform == platform) {
				t.Errorf("%s carries %s: %v", s.Name, sig.ID, has)
			}
		}
		if s.Signatures != len(db.For(platform)) || s.DBVersion != db.Version {
			t.Errorf("%s: %d signatures, db %s", s.Name, s.Signatures, s.DBVersion)
		}
	}
}
