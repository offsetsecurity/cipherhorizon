package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pki", "testdata", "crl", name+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPolicy(t *testing.T) {
	strict, private, loop := Policy{}, Policy{AllowPrivate: true}, Policy{AllowLoopback: true}
	for _, c := range []struct {
		ip                      string
		strict, private, loopOK bool
	}{
		{"8.8.8.8", true, true, true},
		{"2001:4860:4860::8888", true, true, true},
		{"10.1.2.3", false, true, false},
		{"172.16.0.1", false, true, false},
		{"192.168.1.1", false, true, false},
		{"100.64.0.1", false, true, false},
		{"fd00::1", false, true, false},
		{"64:ff9b::a01:203", false, true, false}, // NAT64 of 10.1.2.3
		{"127.0.0.1", false, false, true},
		{"::1", false, false, true},
		{"169.254.169.254", false, false, false},
		{"fe80::1", false, false, false},
		{"0.0.0.0", false, false, false},
		{"0.1.2.3", false, false, false},
		{"224.0.0.1", false, false, false},
		{"168.63.129.16", false, false, false},
		{"100.100.100.200", false, false, false},
	} {
		ip := net.ParseIP(c.ip)
		for _, p := range []struct {
			pol  Policy
			want bool
			name string
		}{{strict, c.strict, "strict"}, {private, c.private, "private"}, {loop, c.loopOK, "loopback"}} {
			err := p.pol.CheckIP(ip)
			if (err == nil) != p.want || (err != nil && !errors.Is(err, ErrBlocked)) {
				t.Errorf("%s under %s policy: %v", c.ip, p.name, err)
			}
		}
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"http://crl.example.com/a.crl", "HTTP://crl.example.com:8080/x?y=1"} {
		if _, err := CheckURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://crl.example.com/a.crl", "ldap://ldap.example.com/cn=CA?certificateRevocationList", "file:///etc/passwd",
		"http://user:pw@crl.example.com/a.crl", "http:///nohost.crl", "gopher://x/", "http://" + strings.Repeat("a", 2100) + ".com/"} {
		if _, err := CheckURL(bad); !errors.Is(err, ErrBlocked) {
			t.Errorf("%.60s: accepted (%v)", bad, err)
		}
	}
}

// server serves body (counting requests) at /crl and redirects elsewhere.
func server(t *testing.T, body []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/crl", func(w http.ResponseWriter, _ *http.Request) { n.Add(1); _, _ = w.Write(body) })
	mux.HandleFunc("/pem", func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		_ = pem.Encode(w, &pem.Block{Type: "X509 CRL", Bytes: body})
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) { n.Add(1); http.NotFound(w, nil) })
	mux.HandleFunc("/html", func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte("<html>not a crl</html>"))
	})
	mux.HandleFunc("/to-https", func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Redirect(w, r, "https://crl.example.com/a.crl", http.StatusFound)
	})
	mux.HandleFunc("/to-crl", func(w http.ResponseWriter, r *http.Request) { n.Add(1); http.Redirect(w, r, "/crl", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { n.Add(1); http.Redirect(w, r, "/loop", http.StatusFound) })
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &n
}

func TestFetcherRefusesLoopbackByDefault(t *testing.T) {
	s, n := server(t, fixture(t, "int-empty"))
	_, err := New(Policy{}).Get(context.Background(), s.URL+"/crl")
	if !errors.Is(err, ErrBlocked) || n.Load() != 0 {
		t.Fatalf("loopback fetched under the default policy: %v (requests %d)", err, n.Load())
	}
	// A name that resolves to loopback is refused at connect time, after DNS.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	if _, err := New(Policy{}).Get(context.Background(), "http://localhost:"+port+"/crl"); !errors.Is(err, ErrBlocked) || n.Load() != 0 {
		t.Fatalf("localhost fetched under the default policy: %v", err)
	}
}

func TestFetcherFetchesParsesAndCaches(t *testing.T) {
	der := fixture(t, "int-empty")
	s, n := server(t, der)
	f := New(Policy{AllowLoopback: true})
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f.Now = func() time.Time { return now }

	got, err := f.Get(context.Background(), s.URL+"/crl")
	if err != nil || got.List == nil || got.Size != len(der) || len(got.SHA256) != 64 || !got.FetchedAt.Equal(now) {
		t.Fatalf("fetch: %+v %v", got, err)
	}
	if _, err := f.Get(context.Background(), s.URL+"/crl"); err != nil || n.Load() != 1 {
		t.Fatalf("second fetch not cached: %v, %d requests", err, n.Load())
	}
	now = now.Add(maxTTL + time.Minute) // past the cache's one-day ceiling
	if _, err := f.Get(context.Background(), s.URL+"/crl"); err != nil || n.Load() != 2 {
		t.Fatalf("expired entry not refetched: %d requests", n.Load())
	}
	if p, err := f.Get(context.Background(), s.URL+"/pem"); err != nil || p.SHA256 != got.SHA256 {
		t.Errorf("PEM CRL: %+v %v", p, err)
	}
	if r, err := f.Get(context.Background(), s.URL+"/to-crl"); err != nil || r.SHA256 != got.SHA256 {
		t.Errorf("redirect within http: %v", err)
	}
}

func TestFetcherFailures(t *testing.T) {
	s, n := server(t, fixture(t, "int-empty"))
	f := New(Policy{AllowLoopback: true})
	for path, want := range map[string]string{
		"/missing":  "HTTP 404",
		"/html":     "not a CRL",
		"/to-https": "only http",
		"/loop":     "redirects",
	} {
		if _, err := f.Get(context.Background(), s.URL+path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	before := n.Load()
	if _, err := f.Get(context.Background(), s.URL+"/missing"); err == nil || n.Load() != before {
		t.Errorf("a failure was not cached briefly: %d -> %d", before, n.Load())
	}
	small := New(Policy{AllowLoopback: true})
	small.MaxBytes = 100
	if _, err := small.Get(context.Background(), s.URL+"/crl"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized CRL: %v", err)
	}
}

func TestFetcherSharesOneRequest(t *testing.T) {
	der := fixture(t, "int-empty")
	var n atomic.Int32
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		<-release
		_, _ = w.Write(der)
	}))
	defer s.Close()
	f := New(Policy{AllowLoopback: true})
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Get(context.Background(), s.URL+"/crl"); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n.Load() != 1 {
		t.Errorf("%d requests for one URL", n.Load())
	}
}

// bigCRL is a well-formed dummy CRL listing n serials.
func bigCRL(t *testing.T, n int) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Dummy CRL Issuer"},
		KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ents := make([]x509.RevocationListEntry, n)
	for i := range ents {
		ents[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(i + 2)), RevocationTime: now.Add(-time.Hour)}
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(12 * time.Hour), RevokedCertificateEntries: ents}, issuer, k)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func cachedWeight(f *Fetcher) (int64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var w int64
	for k, e := range f.cache {
		w += entryWeight(k, e.f, e.err)
	}
	return w, len(f.cache)
}

func TestCRLCacheKeepsToItsByteBudget(t *testing.T) {
	crl := bigCRL(t, 20000)
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { n.Add(1); _, _ = w.Write(crl) }))
	defer s.Close()

	f := New(Policy{AllowLoopback: true})
	f.CacheBytes = 16 << 20
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f.Now = func() time.Time { return now }

	before := heapInUse()
	for i := range 24 { // every query string is a distinct cache key
		if _, err := f.Get(context.Background(), fmt.Sprintf("%s/crl?%d", s.URL, i)); err != nil {
			t.Fatal(err)
		}
		if w, _ := cachedWeight(f); w > f.CacheBytes {
			t.Fatalf("after %d fetches the cache weighs %d bytes, over its %d-byte budget", i+1, w, f.CacheBytes)
		}
	}
	if grew := int64(heapInUse()) - int64(before); grew > 2*f.CacheBytes {
		t.Errorf("24 cached CRLs keep %d bytes of heap; the budget is %d", grew, f.CacheBytes)
	}
	// The newest entries are the ones kept.
	if _, err := f.Get(context.Background(), s.URL+"/crl?23"); err != nil || n.Load() != 24 {
		t.Errorf("the newest entry was evicted: %v, %d requests", err, n.Load())
	}

	// Past their expiry the entries are released to make room, not kept until the count forces it.
	now = now.Add(maxTTL + time.Hour)
	if _, err := f.Get(context.Background(), s.URL+"/crl?fresh"); err != nil {
		t.Fatal(err)
	}
	if _, count := cachedWeight(f); count != 1 {
		t.Errorf("%d entries cached after the others expired, want 1", count)
	}

	// A CRL heavier than the whole budget is used but not kept.
	tiny := New(Policy{AllowLoopback: true})
	tiny.CacheBytes = int64(len(crl))
	for range 2 {
		if got, err := tiny.Get(context.Background(), s.URL+"/crl?big"); err != nil || got.List == nil {
			t.Fatalf("over-budget CRL not returned: %v", err)
		}
	}
	if w, count := cachedWeight(tiny); w != 0 || count != 0 {
		t.Errorf("an over-budget CRL was cached: %d entries, %d bytes", count, w)
	}
}
