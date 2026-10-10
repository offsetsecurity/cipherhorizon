package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// PRD-007 REQ-SX-1: a scan through each STARTTLS protocol finds the same protocols, suites and
// groups as a direct scan of the same TLS configuration, and skips the HTTP check.
func TestSTARTTLSMatchesDirectTLS(t *testing.T) {
	cfg := testserver.Config{MinVersion: tls.VersionTLS12, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}}
	opts := tlsprobe.Options{Timeout: 3 * time.Second, Concurrency: 8, HTTPChecks: true}
	direct := scanOf(t, testserver.Start(t, cfg).Addr, "none", opts)
	if len(direct.Suites) == 0 {
		t.Fatal("the direct scan found no suites")
	}
	for _, proto := range tlsprobe.StartTLSProtocols {
		t.Run(proto, func(t *testing.T) {
			c := cfg
			c.StartTLS = proto
			rep := scanOf(t, testserver.Start(t, c).Addr, proto, opts)
			if rep.Target.StartTLS != proto {
				t.Errorf("report target STARTTLS = %q", rep.Target.StartTLS)
			}
			if got, want := protoSet(rep), protoSet(direct); got != want {
				t.Errorf("protocols %s, direct %s", got, want)
			}
			if got, want := suiteSet(rep), suiteSet(direct); got != want {
				t.Errorf("suites differ:\n starttls %s\n direct   %s", got, want)
			}
			if got, want := groupSet(rep), groupSet(direct); got != want {
				t.Errorf("groups %s, direct %s", got, want)
			}
			if rep.Negotiated == nil || rep.Negotiated.Error != "" || len(rep.Certificates) == 0 {
				t.Errorf("the crypto/tls steps did not run over STARTTLS: %+v, %d certificates", rep.Negotiated, len(rep.Certificates))
			}
			for _, st := range rep.Stages {
				if st.Name == tlsprobe.StageHTTP && (st.Outcome != tlsprobe.OutcomeSkipped || st.ReasonCode != tlsprobe.ReasonNotApplicable) {
					t.Errorf("HTTP stage over STARTTLS: %+v; want skipped as not applicable", st)
				}
			}
		})
	}
}

// REQ-SX-4: a service that refuses STARTTLS, or is not the protocol, fails quickly and says why.
func TestSTARTTLSRefusalIsExplained(t *testing.T) {
	opts := tlsprobe.Options{Timeout: 2 * time.Second, Concurrency: 4}
	for _, proto := range tlsprobe.StartTLSProtocols {
		t.Run(proto, func(t *testing.T) {
			srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, StartTLS: proto, RefuseStartTLS: true})
			start := time.Now()
			target, _ := tlsprobe.ParseTargetStartTLS(srv.Addr, proto)
			rep, err := tlsprobe.Scan(context.Background(), target, opts)
			var se *tlsprobe.StartTLSError
			if !errors.As(err, &se) {
				t.Fatalf("err = %v; want a StartTLSError", err)
			}
			if !strings.Contains(err.Error(), tlsprobe.StartTLSName(proto)) {
				t.Errorf("the error does not name the protocol: %v", err)
			}
			if time.Since(start) > 1500*time.Millisecond {
				t.Errorf("a refusal took %v: it must not wait for a timeout", time.Since(start))
			}
			if rep == nil || !rep.Incomplete || rep.Connections > 2 {
				t.Errorf("report after a refusal: %+v", rep)
			}
		})
	}
	// A plain direct-TLS server asked for SMTP is not the protocol.
	direct := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	target, _ := tlsprobe.ParseTargetStartTLS(direct.Addr, "smtp")
	_, err := tlsprobe.Scan(context.Background(), target, opts)
	var se *tlsprobe.StartTLSError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "SMTP") {
		t.Errorf("SMTP against a direct TLS server: %v", err)
	}
}

// REQ-SX-2: the choice, by flag or scheme, and the well-known ports.
func TestSTARTTLSChoice(t *testing.T) {
	for _, c := range []struct {
		in, choice string
		host       string
		port       int
		proto      string
		bad        bool
	}{
		{"mail.example.com:25", "auto", "mail.example.com", 25, "smtp", false},
		{"mail.example.com:587", "auto", "mail.example.com", 587, "smtp", false},
		{"mail.example.com:465", "auto", "mail.example.com", 465, "", false},
		{"mail.example.com:143", "auto", "mail.example.com", 143, "imap", false},
		{"mail.example.com:110", "auto", "mail.example.com", 110, "pop3", false},
		{"files.example.com:21", "auto", "files.example.com", 21, "ftp", false},
		{"chat.example.com:5222", "auto", "chat.example.com", 5222, "xmpp", false},
		{"dir.example.com:389", "auto", "dir.example.com", 389, "ldap", false},
		{"db.example.com:5432", "auto", "db.example.com", 5432, "postgres", false},
		{"www.example.com", "auto", "www.example.com", 443, "", false},
		{"mail.example.com:25", "none", "mail.example.com", 25, "", false},
		{"mail.example.com:2525", "smtp", "mail.example.com", 2525, "smtp", false},
		{"db.example.com:6432", "PostgreSQL", "db.example.com", 6432, "postgres", false},
		{"smtp://mail.example.com", "auto", "mail.example.com", 25, "smtp", false},
		{"submission://mail.example.com", "none", "mail.example.com", 587, "smtp", false},
		{"imap://[2001:db8::1]:1143", "auto", "2001:db8::1", 1143, "imap", false},
		{"ldaps://dir.example.com", "auto", "dir.example.com", 636, "", false},
		{"https://www.example.com/path?q=1", "auto", "www.example.com", 443, "", false},
		{"gopher://x", "auto", "", 0, "", true},
		{"mail.example.com:25", "smtpx", "", 0, "", true},
	} {
		got, err := tlsprobe.ParseTargetStartTLS(c.in, c.choice)
		if c.bad {
			if err == nil {
				t.Errorf("%s (%s): accepted %+v", c.in, c.choice, got)
			}
			continue
		}
		if err != nil || got.Host != c.host || got.Port != c.port || got.StartTLS != c.proto {
			t.Errorf("%s (%s) = %+v, %v; want %s:%d %q", c.in, c.choice, got, err, c.host, c.port, c.proto)
		}
	}
}

func scanOf(t *testing.T, addr, choice string, opts tlsprobe.Options) *tlsprobe.Report {
	t.Helper()
	target, err := tlsprobe.ParseTargetStartTLS(addr, choice)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tlsprobe.Scan(context.Background(), target, opts)
	if err != nil {
		t.Fatalf("scan %s (%s): %v", addr, choice, err)
	}
	return rep
}

func protoSet(r *tlsprobe.Report) string {
	var s []string
	for _, p := range r.Protocols {
		if p.Supported {
			s = append(s, p.Version)
		}
	}
	return strings.Join(s, ",")
}

func suiteSet(r *tlsprobe.Report) string {
	var s []string
	for _, x := range r.Suites {
		s = append(s, x.Version+"/"+x.Name)
	}
	return strings.Join(s, ",")
}

func groupSet(r *tlsprobe.Report) string {
	var s []string
	for _, g := range r.Groups {
		s = append(s, g.Name)
	}
	return strings.Join(s, ",")
}
