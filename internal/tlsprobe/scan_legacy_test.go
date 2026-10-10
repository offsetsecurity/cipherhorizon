package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// Servers the standard library cannot be: SSLv3, export-grade and NULL suites,
// SSLv2. A scripted server parses the client's offered suites and answers as the
// described server would.

func scanScripted(t *testing.T, s *testserver.Server) *tlsprobe.Report {
	t.Helper()
	o := opts()
	o.SkipCertificates = true // the scripted server cannot complete a handshake
	return scan(t, s, o)
}

func TestSSLv3ServerWithExportAndNullSuites(t *testing.T) {
	// A deliberately terrible server, in the order it prefers them.
	order := []uint16{
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		0x0001, // TLS_RSA_WITH_NULL_MD5
		0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
	}
	srv := testserver.StartScript(t, testserver.Legacy(0x0300, order, false))
	rep := scanScripted(t, srv)

	if got := supported(rep); strings.Join(got, ",") != "SSLv3" {
		t.Fatalf("supported = %v, want only SSLv3 (the server downgrades everything to SSLv3)", got)
	}
	// Every suite is found, in the server's order, including ones crypto/tls can
	// neither offer nor name.
	var got []uint16
	for _, s := range rep.Suites {
		got = append(got, s.ID)
	}
	if len(got) != len(order) {
		t.Fatalf("found %v, want %v", got, order)
	}
	for i := range order {
		if got[i] != order[i] {
			t.Errorf("position %d: 0x%04X, want 0x%04X (server order)", i, got[i], order[i])
		}
	}
	for i, s := range rep.Suites {
		if s.Rank != i+1 {
			t.Errorf("rank of %s = %d, want %d", s.Name, s.Rank, i+1)
		}
	}

	byID := map[uint16]tlsprobe.SuiteResult{}
	for _, s := range rep.Suites {
		byID[s.ID] = s
	}
	if s := byID[0x0003]; !s.Export || s.KeyBits != 40 || s.Cipher != "RC4" || s.IANARecommended != "D" {
		t.Errorf("export suite: %+v", s)
	}
	if s := byID[0x0001]; s.Cipher != "NULL" || s.MAC != "MD5" {
		t.Errorf("NULL suite: %+v", s)
	}
	if s := byID[0x0018]; !s.Anon || s.Auth != "anon" {
		t.Errorf("anonymous suite: %+v", s)
	}
	if s := byID[0x000A]; s.BlockBits != 64 || s.KeyBits != 168 {
		t.Errorf("3DES suite: %+v", s)
	}

	var pref string
	for _, p := range rep.Preference {
		if p.Version == "SSLv3" && p.Subject == "suites" {
			pref = p.Order
		}
	}
	if pref != "server" {
		t.Errorf("SSLv3 preference = %q, want server", pref)
	}
	// Nothing can be concluded from SSLv3 hellos about extensions.
	if rep.Features.SecureRenegotiation != nil || rep.Features.OCSPStapling != nil {
		t.Errorf("features reported from an SSLv3-only server: %+v", rep.Features)
	}
	// The other versions must have been refused, and conclusively.
	for _, p := range rep.Protocols {
		if p.Version != "SSLv3" && (p.Supported || p.Evidence == tlsprobe.EvidenceInconclusive) {
			t.Errorf("%s: %+v", p.Version, p)
		}
	}
}

func TestPreferenceVerdicts(t *testing.T) {
	set := []uint16{0x002F, 0xC013, 0xC014, 0xC027} // in registry (ID) order

	// A server with its own order, different from the registry's.
	serverOrder := []uint16{0xC027, 0xC014, 0x002F, 0xC013}
	rep := scanScripted(t, testserver.StartScript(t, testserver.Legacy(0x0301, serverOrder, false)))
	var got []uint16
	for _, s := range rep.Suites {
		got = append(got, s.ID)
	}
	if len(got) != 4 {
		t.Fatalf("suites = %v", got)
	}
	for i, id := range serverOrder {
		if got[i] != id || rep.Suites[i].Rank != i+1 {
			t.Errorf("server-order scan: position %d is 0x%04X rank %d, want 0x%04X rank %d", i, got[i], rep.Suites[i].Rank, id, i+1)
		}
	}
	if rep.Preference[0].Order != "server" {
		t.Errorf("preference = %+v", rep.Preference)
	}

	// A server that follows the client: no ranking exists and none may be invented.
	rep = scanScripted(t, testserver.StartScript(t, testserver.Legacy(0x0301, set, true)))
	if len(rep.Suites) != 4 {
		t.Fatalf("suites = %+v", rep.Suites)
	}
	if rep.Preference[0].Order != "client" {
		t.Errorf("preference = %+v, want client", rep.Preference)
	}
	for _, s := range rep.Suites {
		if s.Rank != 0 {
			t.Errorf("client-order server got a rank: %+v", s)
		}
	}
}

func TestSSLv2Detection(t *testing.T) {
	srv := testserver.StartScript(t, func(in []byte) []byte {
		if len(in) > 0 && in[0]&0x80 != 0 {
			// SERVER-HELLO: hit 0, cert type 1, version 2, cert len 0, specs len 6, conn id len 0
			body := []byte{4, 0, 1, 0, 2, 0, 0, 0, 6, 0, 0, 0x01, 0x00, 0x80, 0x06, 0x00, 0x40}
			return append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
		}
		return testserver.Alert(70)
	})
	rep := scanScripted(t, srv)

	var v2 *tlsprobe.ProtocolResult
	for i := range rep.Protocols {
		if rep.Protocols[i].Version == "SSLv2" {
			v2 = &rep.Protocols[i]
		}
	}
	if v2 == nil || !v2.Supported || v2.Evidence != tlsprobe.EvidenceServerHello {
		t.Fatalf("SSLv2 result = %+v", v2)
	}
	for _, name := range []string{"SSL_CK_RC4_128_WITH_MD5", "SSL_CK_DES_64_CBC_WITH_MD5"} {
		if !strings.Contains(v2.Detail, name) {
			t.Errorf("detail %q lacks %s", v2.Detail, name)
		}
	}
	if s := supported(rep); len(s) != 1 || s[0] != "SSLv2" {
		t.Errorf("supported = %v, want only SSLv2", s)
	}
}

// A server with SSLv2 disabled answers the SSLv2 hello with nothing or a TLS
// alert, and that must read as "not supported", not as an error.
func TestSSLv2NotSupported(t *testing.T) {
	srv := testserver.StartScript(t, testserver.Legacy(0x0303, []uint16{0xC02F}, false))
	rep := scanScripted(t, srv)
	for _, p := range rep.Protocols {
		if p.Version == "SSLv2" && (p.Supported || p.Evidence == tlsprobe.EvidenceInconclusive) {
			t.Errorf("SSLv2 = %+v", p)
		}
	}
}

func TestFeaturesFromARealServer(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, Cert: testserver.CertRSA})
	f := scan(t, srv, opts()).Features

	if f.SecureRenegotiation == nil || !*f.SecureRenegotiation || f.ExtendedMasterSecret == nil || !*f.ExtendedMasterSecret {
		t.Errorf("renegotiation/EMS: %+v", f)
	}
	if f.Compression == nil || *f.Compression {
		t.Errorf("compression: %v", f.Compression)
	}
	// crypto/tls enforces TLS_FALLBACK_SCSV.
	if f.FallbackSCSV == nil || !*f.FallbackSCSV {
		t.Errorf("FallbackSCSV = %v, want enforced", f.FallbackSCSV)
	}
}

// The scanner must survive whatever answers on the port.
func TestHostileServersDoNotPanicOrHang(t *testing.T) {
	for name, reply := range map[string]func([]byte) []byte{
		"garbage":         func([]byte) []byte { return []byte{22, 3, 3, 0xFF, 0xFF, 1, 2, 3} },
		"truncated hello": func([]byte) []byte { return []byte{22, 3, 3, 0, 20, 2, 0, 0, 16} },
		"alert storm":     func([]byte) []byte { return testserver.Alert(80) },
		"wrong hello":     func([]byte) []byte { return testserver.ServerHello(0xABCD, 0xFFFF) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := testserver.StartScript(t, reply)
			o := opts()
			o.SkipCertificates = true
			rep, _ := tlsprobe.Scan(context.Background(), target(t, srv), o)
			if rep == nil {
				t.Fatal("nil report")
			}
			if len(supported(rep)) != 0 {
				t.Errorf("hostile server reported as supporting %v", supported(rep))
			}
		})
	}
}
