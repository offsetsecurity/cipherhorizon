package server

import (
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// QA of real scans (badssl.com): the list's certificate expiry is the served leaf's, never the
// placeholder a server gives clients that send no server name (badssl.com's expired 2018 fallback).
func TestCertExpiryIgnoresTheNoSNIChain(t *testing.T) {
	served := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	fallback := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	rep := &tlsprobe.Report{Certificates: []tlsprobe.CertResult{
		{Chain: []tlsprobe.CertInfo{{NotAfter: served}}},
		{NoSNI: true, Chain: []tlsprobe.CertInfo{{NotAfter: fallback}}},
	}}
	if got := leafNotAfter(rep); got == nil || !got.Equal(served) {
		t.Errorf("expiry %v, want the served leaf's %v", got, served)
	}
	only := &tlsprobe.Report{Certificates: []tlsprobe.CertResult{{NoSNI: true, Chain: []tlsprobe.CertInfo{{NotAfter: fallback}}}}}
	if got := leafNotAfter(only); got != nil {
		t.Errorf("only a no-SNI chain: expiry %v, want none", got)
	}
}
