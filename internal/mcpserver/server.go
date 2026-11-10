// Package mcpserver exposes CipherHorizon to assistants over the Model Context Protocol
// (PRD-020): ad-hoc TLS and SSH scans that run the same probe and evaluation as the CLI, and,
// when a CipherHorizon server is configured, the fleet (endpoints, stored scans, findings,
// standards conformance, host inventory) through that server's HTTP API, so its roles, audit
// trail and scan scope apply unchanged.
//
// The model is an untrusted caller. Every scan passes the server's Guard; the operator can
// narrow it (--scan-allow), remove the scan tools (--no-scan) or every mutating tool
// (--read-only). Results are bounded in size and come with the text a reader would see.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Options configures New.
type Options struct {
	Version string
	Log     *slog.Logger // nil: nothing is logged

	// Scan configures the ad-hoc tls_scan and ssh_scan tools. NoScan leaves them out.
	Scan   ScanOptions
	NoScan bool

	// Fleet, when set, adds the tools that read and (unless ReadOnly) change a CipherHorizon
	// server's fleet through its HTTP API.
	Fleet    *Fleet
	ReadOnly bool

	// Verdict writes the verdict text the CLI prints for an evaluation; Details writes what
	// --details adds. Both are injected so this package does not depend on the CLI.
	Verdict func(w io.Writer, target string, ev eval.Evaluation) error
	Details func(w io.Writer, rep any, ev eval.Evaluation) error

	Now func() time.Time
}

// ScanOptions bounds the ad-hoc scans.
type ScanOptions struct {
	Guard server.Guard
	// Timeout is the per-connection timeout; Concurrency the connections in flight to a target;
	// MaxConnections the cap per TLS target.
	Timeout        time.Duration
	Concurrency    int
	MaxConnections int
	HTTPChecks     bool
}

// Server is the MCP server with the options it was built from.
type Server struct {
	*mcp.Server
	opts Options
}

// New builds the MCP server: tools in a fixed order, the resources and the prompts.
func New(opts Options) *Server {
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Scan.Timeout == 0 {
		opts.Scan.Timeout = 8 * time.Second
	}
	if opts.Scan.Concurrency == 0 {
		opts.Scan.Concurrency = 4
	}
	if opts.Scan.MaxConnections == 0 {
		opts.Scan.MaxConnections = 2000
	}
	s := &Server{opts: opts}
	s.Server = mcp.NewServer(&mcp.Implementation{Name: "cipherhorizon", Title: "CipherHorizon", Version: opts.Version},
		&mcp.ServerOptions{Instructions: s.instructions(), Logger: opts.Log})
	if !opts.NoScan {
		s.addScanTools()
	}
	if opts.Fleet != nil {
		s.addFleetTools()
	}
	s.addResources()
	s.addPrompts()
	return s
}

func (s *Server) instructions() string {
	var b strings.Builder
	b.WriteString("CipherHorizon measures the cryptographic posture of TLS and SSH endpoints: post-quantum readiness " +
		"(a level from L0 to L4), the TLS hygiene score (0 to 100), findings with remediation, conformance to published " +
		"standards clause by clause (NIST SP 800-52, BSI TR-02102, BCP 195, CNSA 2.0, ...), what named clients would " +
		"negotiate, and a CycloneDX CBOM of what was observed. Use the product's own words: readiness levels L0–L4, " +
		"hygiene bands Excellent/Good/Fair/Poor/Failing, standards verdicts meets / does not meet / not assessed. " +
		"Never present a grade or vocabulary from another scanner as this product's.\n\n")
	switch {
	case s.opts.NoScan && s.opts.Fleet == nil:
		b.WriteString("This server exposes only the reference catalogues (resources); no tool connects anywhere.\n")
	case s.opts.NoScan:
		b.WriteString("Ad-hoc scanning is turned off here; the fleet tools answer from scans the CipherHorizon server has stored.\n")
	default:
		b.WriteString("tls_scan and ssh_scan connect to the target and make a few hundred short handshakes (TLS) or at most 24 " +
			"connections (SSH); they never log in and never send application data beyond one HTTP GET / for headers. " +
			"Scan only systems the user is authorised to test. ")
		if s.opts.Scan.Guard.Scope != nil {
			b.WriteString("The operator limited scans to a scope; a target outside it is refused.\n")
		} else {
			b.WriteString("Link-local, metadata and (unless allowed) loopback addresses are refused.\n")
		}
	}
	if s.opts.Fleet != nil {
		b.WriteString("\nThe fleet tools talk to a CipherHorizon server at " + s.opts.Fleet.Base + ". ")
		if s.opts.ReadOnly {
			b.WriteString("This server is read-only: it cannot add endpoints or start stored scans.\n")
		} else {
			b.WriteString("endpoint_add records a target; scan_start queues a stored scan of it; scan_get follows the scan " +
				"(poll it until status is done or failed) and returns the verdict.\n")
		}
	}
	return b.String()
}

// ---- helpers ----------------------------------------------------------------------------------------

func ptr[T any](v T) *T { return &v }

// readOnly annotates a tool that changes nothing; network says whether it touches an open world.
func readOnly(title string, network bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(network)}
}

// additive annotates a tool that adds to the server's state without destroying anything.
func additive(title string, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: idempotent, OpenWorldHint: ptr(false)}
}

// failf is a tool execution error: the model reads it and can correct its call.
func failf[Out any](format string, args ...any) (*mcp.CallToolResult, Out, error) {
	var zero Out
	return nil, zero, fmt.Errorf(format, args...)
}

// textResult returns text content beside a structured value.
func textResult[Out any](text string, out Out) (*mcp.CallToolResult, Out, error) { //nolint:unparam // the shape every handler returns
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// maxJSON caps a "full" result: a TLS evaluation with every check, suite and client runs to a few
// hundred KiB; past this the model is told what was cut rather than handed a truncated document.
const maxJSON = 200 << 10

// compactJSON renders v, or says what to do when it is too large.
func compactJSON(v any) (json.RawMessage, string) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "could not encode: " + err.Error()
	}
	if len(raw) > maxJSON {
		return nil, fmt.Sprintf("the full result is %d KiB, over the %d KiB this tool returns; ask for detail \"findings\" or narrow the request", len(raw)>>10, maxJSON>>10)
	}
	return raw, ""
}

// targetName names a TLS target the way the CLI does.
func targetName(t tlsprobe.Target) string {
	name := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	if t.StartTLS != "" {
		name += " via STARTTLS (" + tlsprobe.StartTLSName(t.StartTLS) + ")"
	}
	return name
}

// ctxErr says whether the call was cancelled by the client.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("the request was cancelled before the scan finished")
	}
	return nil
}
