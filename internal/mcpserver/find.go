package mcpserver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/namefind"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

// FindOptions configures domain_find (PRD-022, internal).
type FindOptions struct {
	// Resolver answers DNS queries (default: the system resolver).
	Resolver namefind.Resolver
	// CT searches Certificate Transparency, and CTAllowed says whether the operator turned that
	// on. With either unset the tool refuses certificateLogs with the reason.
	CT        namefind.CTSearcher
	CTAllowed func() bool
	// Dial replaces the guarded dialer of the port checks (tests).
	Dial func(ctx context.Context, address string, port int) (net.Conn, error)
	// Timeout bounds one call (default 10 minutes).
	Timeout time.Duration
}

// findMaxNames caps what one call returns: an assistant's context is not the place for a zone.
const findMaxNames = 500

// FindInput is what domain_find takes.
type FindInput struct {
	Domain          string `json:"domain" jsonschema:"the domain alone, such as example.com"`
	Wordlist        bool   `json:"wordlist,omitempty" jsonschema:"also try about 1,600 common labels (www, mail, vpn, dev-api ...); adds a few thousand DNS queries and about a minute"`
	CertificateLogs bool   `json:"certificateLogs,omitempty" jsonschema:"also search Certificate Transparency logs. This sends the domain name to an outside service and works only where the operator turned it on"`
}

// FoundName is one name in a domain_find result.
type FoundName struct {
	Name      string   `json:"name"`
	Sources   []string `json:"sources" jsonschema:"which sources reported the name: domain, dns, ct, wordlist"`
	Addresses []string `json:"addresses"`
	CNAME     string   `json:"cname,omitempty"`
	External  bool     `json:"external,omitempty" jsonschema:"the name is an alias for a host outside the domain: the service is hosted elsewhere"`
	Ports     []int    `json:"ports" jsonschema:"the ports among 443, 8443, 22 (and 25 on mail servers) that accepted a connection"`
	Refused   string   `json:"refused,omitempty" jsonschema:"why the name may not be connected to from here"`
}

// FindResult is the structured half of domain_find's answer.
type FindResult struct {
	Domain string `json:"domain"`
	// Total is how many names were found; Names holds those that resolve, at most 500.
	Total     int                     `json:"total"`
	Resolving int                     `json:"resolving"`
	Answering int                     `json:"answering" jsonschema:"names on which at least one port answered"`
	Names     []FoundName             `json:"names"`
	Cut       int                     `json:"cut,omitempty" jsonschema:"resolving names left out of names because of the 500 limit"`
	Sources   []namefind.SourceReport `json:"sources" jsonschema:"what each source did: ran, off or failed"`
	Limits    []string                `json:"limits" jsonschema:"what this run could not see"`
}

func (s *Server) addFindTool() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "domain_find",
		Title: "Find the host names under a domain",
		Description: "List the host names under a domain: from the domain's own DNS records (name servers, mail servers, SPF, service records), " +
			"and on request from about 1,600 common labels and from Certificate Transparency logs. Each name is resolved and ports 443, 8443 " +
			"and 22 are tried with one TCP connection each (25 on mail servers); nothing else is sent and nothing is stored or added. " +
			"The answer says which source reported each name and what the run could not see: no source knows every name. " +
			"Use it only for a domain the user owns or is authorised to test, then offer to scan what answered (tls_scan, ssh_scan) " +
			"or to add it (endpoint_add). Takes from a few seconds to a few minutes.",
		Annotations: readOnly("Find the host names under a domain", true),
	}, s.domainFind)
}

func (s *Server) domainFind(ctx context.Context, _ *mcp.CallToolRequest, in FindInput) (*mcp.CallToolResult, FindResult, error) {
	domain, err := namefind.NormalizeDomain(in.Domain)
	if err != nil {
		return failf[FindResult]("%v", err)
	}
	g := s.opts.Scan.Guard
	if err := g.CheckDomain(domain); err != nil {
		return failf[FindResult]("%s cannot be looked under from here: %v", domain, err)
	}
	f := s.opts.Find
	sources := []string{namefind.SourceDNS}
	var ct namefind.CTSearcher
	if in.CertificateLogs {
		if f.CT == nil || f.CTAllowed == nil || !f.CTAllowed() {
			return failf[FindResult]("searching certificate logs is turned off here. It sends the domain name to an outside service; " +
				"an administrator of the CipherHorizon server can turn it on in Settings. Run again without certificateLogs")
		}
		ct = f.CT
		sources = append(sources, namefind.SourceCT)
	}
	if in.Wordlist {
		sources = append(sources, namefind.SourceWordlist)
	}
	base := server.Guard{AllowLoopback: g.AllowLoopback}
	dial := func(ctx context.Context, address string, port int) (net.Conn, error) {
		return base.Dial(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	}
	if f.Dial != nil {
		dial = f.Dial
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s.opts.Log.Info("domain_find", "domain", domain, "sources", strings.Join(sources, ","))
	res, err := namefind.Run(rctx, namefind.Options{
		Domain: domain, Sources: sources, CT: ct, Resolver: f.Resolver, Dial: dial,
		CheckIP: func(host string, ip net.IP) error { return g.ForTarget(host).CheckIP(ip) },
	})
	if err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return failf[FindResult]("%v", cerr)
		}
		return failf[FindResult]("the run did not finish: %v", err)
	}
	out := FindResult{Domain: res.Domain, Total: len(res.Names), Names: []FoundName{}, Limits: []string{}}
	for _, src := range res.Sources {
		if src.ID != namefind.SourceStored && src.ID != namefind.SourceList {
			out.Sources = append(out.Sources, src)
		}
	}
	for _, n := range res.Names {
		if len(n.Addresses) == 0 {
			continue
		}
		out.Resolving++
		if len(n.Ports) > 0 {
			out.Answering++
		}
		if len(out.Names) >= findMaxNames {
			out.Cut++
			continue
		}
		out.Names = append(out.Names, FoundName{Name: n.Name, Sources: n.Sources, Addresses: n.Addresses, CNAME: n.CNAME,
			External: n.External, Ports: n.Ports, Refused: n.Refused})
	}
	for _, src := range out.Sources {
		if src.Status == "failed" {
			out.Limits = append(out.Limits, "A source failed: "+src.Detail+".")
		}
	}
	if !in.CertificateLogs {
		out.Limits = append(out.Limits, "Certificate Transparency logs were not searched; they usually know the most names.")
	}
	if !in.Wordlist {
		out.Limits = append(out.Limits, "Common labels were not tried.")
	}
	if len(res.WildcardCerts) > 0 {
		out.Limits = append(out.Limits, "Wildcard certificates ("+strings.Join(res.WildcardCerts, ", ")+") cover names no source can list.")
	}
	if res.Wildcard {
		out.Limits = append(out.Limits, "The zone answers for any name, so guesses that only matched that answer were dropped.")
	}
	if res.Truncated {
		out.Limits = append(out.Limits, "Collecting stopped at the name limit; there are more.")
	}
	out.Limits = append(out.Limits, "No source knows every name: one absent from all of them is not found. The owner's DNS zone is the complete list.")

	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d names found, %d resolve, %d answer on a port.\n", out.Domain, out.Total, out.Resolving, out.Answering)
	for _, n := range out.Names {
		fmt.Fprintf(&b, "  %s", n.Name)
		switch {
		case n.Refused != "":
			fmt.Fprintf(&b, "  (not reachable from here: %s)", n.Refused)
		case len(n.Ports) == 0:
			b.WriteString("  (nothing answered)")
		default:
			fmt.Fprintf(&b, "  ports %s", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(n.Ports)), ", "), "[]"))
		}
		if n.External {
			fmt.Fprintf(&b, "  hosted elsewhere (%s)", n.CNAME)
		}
		b.WriteString("\n")
	}
	if out.Cut > 0 {
		fmt.Fprintf(&b, "  ... and %d more that resolve.\n", out.Cut)
	}
	b.WriteString("\nWhat this run could not see:\n")
	for _, l := range out.Limits {
		b.WriteString("  " + l + "\n")
	}
	return textResult(b.String(), out)
}
