package eval

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The resumption rules read what the scan's resumption probe recorded (tlsprobe.Resumption): the
// lifetime the server's session tickets state, and whether its TLS 1.3 tickets allow early data.
// A report without the probe leaves these checks "not checked".

var (
	citRFC8470 = rfc("8470", "Using Early Data in HTTP")
	citRFC5077 = rfc("5077", "Transport Layer Security (TLS) Session Resumption without Server-Side State")
)

// maxTicketLifetime is the longest a TLS 1.3 ticket may live (RFC 8446 section 4.6.1: seven days).
const maxTicketLifetime = 7 * 24 * 3600

func duration(seconds uint32) string {
	switch {
	case seconds%86400 == 0 && seconds >= 86400:
		return plural(int(seconds/86400), "day")
	case seconds%3600 == 0 && seconds >= 3600:
		return plural(int(seconds/3600), "hour")
	case seconds%60 == 0 && seconds >= 60:
		return plural(int(seconds/60), "minute")
	}
	return plural(int(seconds), "second")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// ticketLifetimes lists the lifetimes the tickets state, by version, skipping a TLS 1.2 hint of 0
// (which means "unspecified", RFC 5077 section 3.3).
func ticketLifetimes(r *tlsprobe.Resumption) (stated map[string]uint32, unspecified bool) {
	stated = map[string]uint32{}
	if r == nil {
		return stated, false
	}
	if v := r.TLS13; v != nil && v.LifetimeSeconds != nil {
		stated["TLS 1.3"] = *v.LifetimeSeconds
	}
	if v := r.TLS12; v != nil && v.LifetimeSeconds != nil {
		if *v.LifetimeSeconds == 0 {
			unspecified = true
		} else {
			stated["TLS 1.2"] = *v.LifetimeSeconds
		}
	}
	return stated, unspecified
}

var resumptionRules = []rule{
	{id: "FEAT.EARLY-DATA", title: "TLS 1.3 early data (0-RTT) is accepted", category: "feature", severity: Low, evidence: Observed,
		citations:   []Citation{citRFC8446, citRFC9325, citRFC8470},
		remediation: "Turn early data off unless every request the service accepts in it is safe to replay (nginx: ssl_early_data off; HAProxy: remove allow-0rtt; a CDN: its 0-RTT setting). If you keep it for HTTP, follow RFC 8470: accept only safe methods early and honour the Early-Data header. An attacker who records early data can send it again, and it is not protected by this connection's key exchange.",
		check: func(c *ctx) []hit {
			r := c.rep.Resumption
			if r == nil || r.TLS13 == nil || r.TLS13.MaxEarlyData == nil || *r.TLS13.MaxEarlyData == 0 {
				return nil
			}
			return one(fmt.Sprintf("The server's TLS 1.3 session tickets allow up to %d bytes of early data. The scan read this from the tickets and sent no early data.", *r.TLS13.MaxEarlyData))
		}},
	{id: "FEAT.TICKET-LIFETIME", title: "Session tickets are valid for more than seven days", category: "feature", severity: Low, evidence: Observed,
		citations:   []Citation{citRFC9325, citRFC8446, citRFC5077},
		remediation: "Limit session ticket lifetime to a day or less and rotate the ticket-encryption key at least weekly (nginx: ssl_session_timeout 1d, with ssl_session_ticket_key rotated or ssl_session_tickets off; Apache: SSLSessionTicketKeyFile rotated; HAProxy: tune.ssl.lifetime). A stolen ticket key decrypts every session resumed under it, so long-lived tickets undo forward secrecy for that long.",
		check: func(c *ctx) []hit {
			stated, _ := ticketLifetimes(c.rep.Resumption)
			var long []string
			for _, v := range []string{"TLS 1.3", "TLS 1.2"} {
				if s, ok := stated[v]; ok && s > maxTicketLifetime {
					long = append(long, fmt.Sprintf("%s tickets state %s", v, duration(s)))
				}
			}
			if len(long) == 0 {
				return nil
			}
			return one(strings.Join(long, "; ") + ".")
		}},
}

func init() {
	passText["FEAT.EARLY-DATA"] = "The server's TLS 1.3 tickets allow no early data (0-RTT)"
	passText["FEAT.TICKET-LIFETIME"] = "Session tickets state a lifetime of seven days or less"
}

// resumptionChecked reports whether a resumption check could be decided from the report.
func resumptionChecked(rep *tlsprobe.Report, id string) bool {
	r := rep.Resumption
	if r == nil {
		return false
	}
	switch id {
	case "FEAT.EARLY-DATA":
		// No TLS 1.3 means no early data to accept; tickets that could not be read decide nothing.
		return r.TLS13 == nil || r.TLS13.MaxEarlyData != nil || r.TLS13.Tickets == 0
	case "FEAT.TICKET-LIFETIME":
		for _, v := range []*tlsprobe.ResumeResult{r.TLS13, r.TLS12} {
			if v != nil && v.Tickets > 0 && v.LifetimeSeconds == nil {
				return false
			}
		}
	}
	return true
}
