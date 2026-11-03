// Package revocation fetches the CRLs that certificates name, for the opt-in
// revocation stage of a TLS scan (CRYPTO-REVIEW-004 P1b). It is the only code
// in a scan that contacts a host other than the target, so it is careful:
//
//   - The addresses come from certificates the target sent, so they are
//     hostile. Only plain http URLs (RFC 5280 §4.2.1.13; the CA/Browser Forum
//     requires http for CRLs) without credentials are fetched, and Policy is
//     enforced on the real remote address of every connection, redirects
//     included: loopback, link-local (cloud metadata), private, shared and
//     unspecified addresses are refused unless the operator allows them.
//   - Bodies are capped (MaxBytes), requests are timed out, no proxy from the
//     environment is used, and nothing from the response is shown verbatim.
//   - Results are cached by URL until the CRL's nextUpdate (at most a day), and
//     failures for a few minutes, so repeated scans do not hammer a CA.
//
// It only fetches and parses; pki.JudgeCRL decides what a CRL says.
package revocation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Defaults.
const (
	DefaultMaxBytes = 16 << 20
	DefaultTimeout  = 10 * time.Second
	maxURLLen       = 2048
	maxRedirects    = 3
	maxCache        = 512
	errorTTL        = 5 * time.Minute
	maxTTL          = 24 * time.Hour
	minTTL          = 5 * time.Minute
)

// ErrBlocked is wrapped by every refusal of an address or URL.
var ErrBlocked = errors.New("CRL address not allowed")

// Policy says which remote addresses a CRL fetch may connect to.
type Policy struct {
	// AllowPrivate allows RFC 1918, unique-local (fc00::/7) and shared
	// (100.64.0.0/10) addresses: an internal CA's CRL server. Off by default,
	// because any certificate a scanned server presents can name one.
	AllowPrivate bool
	// AllowLoopback allows this machine (tests, and a CA run on the same host).
	AllowLoopback bool
}

// metadata addresses outside the always-refused ranges (kept in step with the
// scan guard's list in internal/server/guard.go).
var metadata = []net.IP{
	net.ParseIP("fd00:ec2::254"), net.ParseIP("100.100.100.200"), net.ParseIP("192.0.0.192"),
	net.ParseIP("255.255.255.255"), net.ParseIP("168.63.129.16"), net.ParseIP("fd00:ec2::23"),
}

var (
	thisNetwork = mustCIDR("0.0.0.0/8")
	shared      = mustCIDR("100.64.0.0/10")
	nat64       = mustCIDR("64:ff9b::/96")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// CheckIP returns nil when a CRL fetch may connect to ip.
func (p Policy) CheckIP(ip net.IP) error {
	if ip != nil && ip.To4() == nil && nat64.Contains(ip) {
		return p.CheckIP(ip.To16()[12:16])
	}
	switch {
	case ip == nil:
		return fmt.Errorf("%w: not an IP address", ErrBlocked)
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return fmt.Errorf("%w: %s is the unspecified address", ErrBlocked, ip)
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address", ErrBlocked, ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("%w: %s is link-local (this range includes cloud metadata services)", ErrBlocked, ip)
	case ip.IsLoopback() && !p.AllowLoopback:
		return fmt.Errorf("%w: %s is a loopback address", ErrBlocked, ip)
	case (ip.IsPrivate() || shared.Contains(ip)) && !p.AllowPrivate:
		return fmt.Errorf("%w: %s is a private address (allow private CRL addresses to fetch an internal CA's CRL)", ErrBlocked, ip)
	}
	for _, m := range metadata {
		if m.Equal(ip) {
			return fmt.Errorf("%w: %s is a known cloud-metadata address", ErrBlocked, ip)
		}
	}
	return nil
}

func (p Policy) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	return p.CheckIP(net.ParseIP(host))
}

// CheckURL refuses anything but a plain http URL with a host and no credentials.
func CheckURL(raw string) (*url.URL, error) {
	if len(raw) > maxURLLen {
		return nil, fmt.Errorf("%w: the URL is longer than %d bytes", ErrBlocked, maxURLLen)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: not a URL", ErrBlocked)
	case !strings.EqualFold(u.Scheme, "http"):
		return nil, fmt.Errorf("%w: only http CRL addresses are fetched (this one is %q)", ErrBlocked, u.Scheme)
	case u.User != nil:
		return nil, fmt.Errorf("%w: the URL carries credentials", ErrBlocked)
	case u.Hostname() == "":
		return nil, fmt.Errorf("%w: the URL has no host", ErrBlocked)
	}
	return u, nil
}

// Fetched is one CRL as retrieved.
type Fetched struct {
	List      *x509.RevocationList
	SHA256    string
	Size      int
	FetchedAt time.Time
}

// Fetcher retrieves CRLs. It is safe for concurrent use; share one per process
// so its cache works across scans.
type Fetcher struct {
	Policy   Policy
	MaxBytes int64
	Timeout  time.Duration
	Now      func() time.Time

	once   sync.Once
	client *http.Client

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]chan struct{}
}

type cacheEntry struct {
	f       *Fetched
	err     error
	expires time.Time
}

// New returns a Fetcher with the default limits.
func New(p Policy) *Fetcher { return &Fetcher{Policy: p} }

func (f *Fetcher) init() {
	f.once.Do(func() {
		if f.MaxBytes <= 0 {
			f.MaxBytes = DefaultMaxBytes
		}
		if f.Timeout <= 0 {
			f.Timeout = DefaultTimeout
		}
		if f.Now == nil {
			f.Now = time.Now
		}
		d := &net.Dialer{Timeout: f.Timeout, Control: f.Policy.control}
		tr := &http.Transport{
			Proxy:                  nil, // never an environment proxy: the guard must see the real address
			DialContext:            d.DialContext,
			ResponseHeaderTimeout:  f.Timeout,
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConns:           8,
			IdleConnTimeout:        30 * time.Second,
			DisableCompression:     true,
		}
		f.client = &http.Client{Transport: tr, Timeout: f.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("%w: more than %d redirects", ErrBlocked, maxRedirects)
				}
				_, err := CheckURL(req.URL.String())
				return err
			}}
		f.cache = map[string]cacheEntry{}
		f.inflight = map[string]chan struct{}{}
	})
}

// Get returns the CRL at raw, from the cache when it is still fresh. Callers
// fetching the same URL at once share one request.
func (f *Fetcher) Get(ctx context.Context, raw string) (*Fetched, error) {
	f.init()
	for {
		f.mu.Lock()
		if e, ok := f.cache[raw]; ok && f.Now().Before(e.expires) {
			f.mu.Unlock()
			return e.f, e.err
		}
		if ch, busy := f.inflight[raw]; busy {
			f.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ch := make(chan struct{})
		f.inflight[raw] = ch
		f.mu.Unlock()

		got, err := f.fetch(ctx, raw)
		f.mu.Lock()
		delete(f.inflight, raw)
		close(ch)
		if ctx.Err() == nil { // a cancelled scan says nothing about the CA
			f.store(raw, got, err)
		}
		f.mu.Unlock()
		return got, err
	}
}

// store caches a result; f.mu is held.
func (f *Fetcher) store(raw string, got *Fetched, err error) {
	now := f.Now()
	exp := now.Add(errorTTL)
	if err == nil {
		exp = now.Add(maxTTL)
		if nu := got.List.NextUpdate; !nu.IsZero() && nu.Before(exp) {
			exp = nu
		}
		if exp.Before(now.Add(minTTL)) {
			exp = now.Add(minTTL)
		}
	}
	if len(f.cache) >= maxCache {
		var oldest string
		var at time.Time
		for k, e := range f.cache {
			if oldest == "" || e.expires.Before(at) {
				oldest, at = k, e.expires
			}
		}
		delete(f.cache, oldest)
	}
	f.cache[raw] = cacheEntry{f: got, err: err, expires: exp}
}

func (f *Fetcher) fetch(ctx context.Context, raw string) (*Fetched, error) {
	u, err := CheckURL(raw)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if err := f.Policy.CheckIP(ip); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	req.Header.Set("Accept", "application/pkix-crl, application/x-pkcs7-crl;q=0.5, */*;q=0.1")
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is already known; keep the cause
		}
		return nil, fmt.Errorf("fetching the CRL failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the CRL server answered HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > f.MaxBytes {
		return nil, fmt.Errorf("the CRL is %d bytes, more than the %d-byte limit", resp.ContentLength, f.MaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the CRL failed: %w", err)
	}
	if int64(len(body)) > f.MaxBytes {
		return nil, fmt.Errorf("the CRL is more than the %d-byte limit", f.MaxBytes)
	}
	der := body
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "X509 CRL" {
		der = blk.Bytes
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("the response is not a CRL (%d bytes)", len(body))
	}
	sum := sha256.Sum256(der)
	return &Fetched{List: rl, SHA256: hex.EncodeToString(sum[:]), Size: len(der), FetchedAt: f.Now().UTC()}, nil
}
