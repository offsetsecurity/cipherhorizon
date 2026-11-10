package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// The resources: the reference catalogues this binary carries, so the model can quote a
// standard's clause, a baseline's source or a client's defaults without a network call.
const (
	uriStandards = "cipherhorizon://standards"
	uriBaselines = "cipherhorizon://ssh-baselines"
	uriClients   = "cipherhorizon://clients"
	uriScale     = "cipherhorizon://readiness-scale"
)

func (s *Server) addResources() {
	s.AddResource(&mcp.Resource{
		URI: uriStandards, Name: "standards", Title: "Published standards, clause by clause", MIMEType: "application/json",
		Description: "Every standard a scan is judged against (NIST SP 800-52, BSI TR-02102, BCP 195, CNSA 2.0, Mozilla, ANSSI, PCI DSS, " +
			"BSI TR-02102-4 for SSH, ...): publisher, edition, URL, each clause judged with its level (must or should), and what a network " +
			"scan cannot assess.",
	}, s.readResource)
	s.AddResource(&mcp.Resource{
		URI: uriBaselines, Name: "ssh-baselines", Title: "SSH baselines", MIMEType: "application/json",
		Description: "The SSH baselines an SSH server can be judged against: allowed algorithms per kind in preference order, with the " +
			"OpenSSH version that introduced each, and the requirements (post-quantum hybrid key exchange, strict key exchange, RSA size).",
	}, s.readResource)
	s.AddResource(&mcp.Resource{
		URI: uriClients, Name: "clients", Title: "Simulated clients", MIMEType: "application/json",
		Description: "The named clients whose handshake a TLS scan simulates offline (browsers, mobile platforms, runtimes, libraries, " +
			"legacy): release date, protocol versions, cipher suites, groups and key shares, with the source of each profile.",
	}, s.readResource)
	s.AddResource(&mcp.Resource{
		URI: uriScale, Name: "readiness-scale", Title: "Readiness levels and hygiene bands", MIMEType: "text/markdown",
		Description: "What the post-quantum readiness levels L0–L4 and the TLS hygiene score and bands mean, in the product's words. " +
			"Read this before explaining a verdict.",
	}, s.readResource)
}

func (s *Server) readResource(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	var text, mime string
	switch uri {
	case uriStandards:
		text, mime = mustJSON(eval.Standards()), "application/json"
	case uriBaselines:
		text, mime = mustJSON(eval.SSHBaselines()), "application/json"
	case uriClients:
		text, mime = mustJSON(eval.Clients()), "application/json"
	case uriScale:
		text, mime = readinessScale(), "text/markdown"
	default:
		return nil, mcp.ResourceNotFoundError(uri)
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mime, Text: text}}}, nil
}

func mustJSON(v any) string {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return `{"error":` + fmt.Sprintf("%q", err.Error()) + `}`
	}
	return string(raw)
}

// readinessScale is the scale in the product's words (the same ones Help uses).
func readinessScale() string {
	var b strings.Builder
	b.WriteString("# Post-quantum readiness levels\n\n")
	b.WriteString("A level says how far an endpoint's key exchange and authentication have moved to post-quantum algorithms. " +
		"It is not a grade of general quality; the TLS hygiene score is.\n\n")
	for l := eval.LevelNotReady; l <= eval.LevelPQAuth; l++ {
		meaning := levelMeaning(l)
		fmt.Fprintf(&b, "- **L%d · %s** — %s\n", l, eval.LevelLabel(l), meaning)
	}
	b.WriteString("- **Undetermined** — the scan could not tell whether TLS 1.3 is supported.\n\n")
	b.WriteString("**HNDL exposed** (harvest now, decrypt later): the key exchange a current client negotiates is classical, so traffic " +
		"recorded today could be read by a future quantum computer. True at L0, L1 and L2.\n\n")
	b.WriteString("SSH servers get the same levels (hybrid key exchange such as mlkem768x25519-sha256 or sntrup761x25519-sha512 counts), " +
		"judged beside an SSH baseline instead of a hygiene score.\n\n")
	b.WriteString("# TLS hygiene score\n\n")
	b.WriteString("Start at 100 and take off points for each finding on this result (critical 40, high 20, medium 10, low 4, info 0). " +
		"Post-quantum findings are not counted; readiness is reported separately. Each distinct problem counts once. " +
		"A critical finding limits the score to 29 (Failing) and a high finding to 74 (Fair).\n\n")
	b.WriteString("Bands: **Excellent** 90 and above, **Good** 75–89, **Fair** 55–74, **Poor** 30–54, **Failing** below 30; " +
		"**Not rated** when the scan saw too little to judge.\n\n")
	b.WriteString("# Standards\n\nEach published standard gets a verdict of its own: **meets** (no must-clause fails), **does not meet** " +
		"(with the clauses), or **not assessed** (nothing could be judged). Standards are never folded into the level or the score.\n")
	return b.String()
}

func levelMeaning(l int) string {
	switch l {
	case eval.LevelNotReady:
		return "no TLS 1.3, so no post-quantum key exchange is possible."
	case eval.LevelExposed:
		return "TLS 1.3, but only classical key exchange."
	case eval.LevelHybridAvail:
		return "a standardised hybrid group (X25519MLKEM768) is supported, but a current client does not negotiate it."
	case eval.LevelHybridNeg:
		return "a current client negotiates a standardised hybrid key exchange: recorded traffic is protected."
	default:
		return "hybrid key exchange and post-quantum authentication: a post-quantum (ML-DSA) certificate is presented to a current client."
	}
}

// ---- prompts --------------------------------------------------------------------------------------

func (s *Server) addPrompts() {
	if !s.opts.NoScan {
		s.AddPrompt(&mcp.Prompt{
			Name: "assess_endpoint", Title: "Assess an endpoint",
			Description: "Scan a TLS or SSH endpoint and explain the result for an engineer: readiness, what to fix first and why, standards not met.",
			Arguments: []*mcp.PromptArgument{
				{Name: "target", Description: "host, host:port or URL (ssh:// for an SSH server)", Required: true},
			},
		}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			target := strings.TrimSpace(req.Params.Arguments["target"])
			if target == "" {
				return nil, fmt.Errorf("target is required")
			}
			tool := "tls_scan"
			if strings.HasPrefix(target, "ssh://") || strings.HasSuffix(target, ":22") {
				tool = "ssh_scan"
			}
			return &mcp.GetPromptResult{
				Description: "Assess " + target,
				Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: fmt.Sprintf(
					"Read the cipherhorizon://readiness-scale resource, then call %s for %q with detail \"findings\". "+
						"Explain the result for the engineer who runs this endpoint: the readiness level and what it means for traffic "+
						"recorded today; the hygiene score (TLS) or baseline conformance (SSH); the three things to fix first, each with "+
						"the concrete configuration change; which published standards it does not meet and the clauses; which named "+
						"clients would stop connecting after the fixes. Use the product's words (L0–L4, Excellent–Failing, meets / does "+
						"not meet). Do not invent measurements the scan did not make.", tool, target)}}},
			}, nil
		})
	}
	if s.opts.Fleet != nil {
		s.AddPrompt(&mcp.Prompt{
			Name: "fleet_review", Title: "Review the fleet",
			Description: "Summarise the fleet's post-quantum readiness and TLS hygiene, the worst findings, and the standards most often missed.",
		}, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "Fleet review",
				Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "Call fleet_summary, standards_summary and " +
					"findings_list (severity critical, then high). Write a review for a security architect: how many endpoints sit at each " +
					"readiness level and how many are exposed to harvest-now-decrypt-later; the hygiene distribution; the five worst " +
					"findings with the endpoints they affect; the standards most often not met and the clause behind it; what to do " +
					"this week, this quarter. Use endpoints_list with only \"not-ready\" or \"failing\" to name endpoints. Use the " +
					"product's words and never another scanner's grades."}}},
			}, nil
		})
	}
}
