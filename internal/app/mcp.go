package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/mcpserver"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// mcpKeyEnv names the bearer key an MCP client must send to the HTTP transport.
const mcpKeyEnv = "CIPHERHORIZON_MCP_KEY"

// mcpCmd runs the Model Context Protocol server (PRD-020): over stdio for a local assistant, or
// over Streamable HTTP with --listen.
func mcpCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	serverURL := fl.String("server", "", "a running CipherHorizon server (URL) whose fleet the assistant may read: endpoints, stored scans, findings, standards, inventory")
	token := fl.String("token", "", "the server's automation token (or "+tokenEnv+")")
	plainHTTP := fl.Bool("allow-plain-http", false, "send the token to an http:// server that is not on this machine")
	readOnly := fl.Bool("read-only", false, "no tool may change the server: endpoint_add and scan_start are left out")
	noScan := fl.Bool("no-scan", false, "leave out tls_scan and ssh_scan, so nothing connects to a target from here")
	var scanAllow stringList
	fl.Var(&scanAllow, "scan-allow", "limit ad-hoc scans to this network (CIDR), address or domain and the names under it (repeatable); "+
		"the same syntax as serve --scan-allow")
	allowLoopback := fl.Bool("allow-loopback", false, "allow ad-hoc scans of this machine's own addresses")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout of an ad-hoc scan")
	httpChecks := fl.Bool("http-checks", true, "after a TLS handshake, send one HTTP GET / and read the Strict-Transport-Security header")
	listen := fl.String("listen", "", "serve Streamable HTTP on this HOST:PORT instead of stdio (the MCP endpoint is /mcp)")
	key := fl.String("key", "", "the bearer key an HTTP client must send (or "+mcpKeyEnv+"); required beyond loopback")
	openNetwork := fl.Bool("open-network", false, "allow --listen beyond loopback without a key: anyone who reaches the port can scan from this machine")
	verbose := fl.Bool("verbose", false, "log every tool call to stderr")
	fl.Usage = func() { mcpUsage(env.Stderr) }
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() != 0 {
		return fatalf(env, "mcp takes no arguments; see cipherhorizon mcp -h")
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: level}))

	scope, err := server.ParseScope(scanAllow)
	if err != nil {
		return fatalf(env, "%v", err)
	}
	opts := mcpserver.Options{
		Version: version.Get().Version, Log: log, ReadOnly: *readOnly, NoScan: *noScan,
		Scan:    mcpserver.ScanOptions{Guard: server.Guard{AllowLoopback: *allowLoopback, Scope: scope}, Timeout: *timeout, HTTPChecks: *httpChecks},
		Verdict: writeVerdict, Details: writeDetails, Now: env.Now,
	}
	if *serverURL != "" {
		tok := *token
		if tok == "" {
			tok = os.Getenv(tokenEnv)
		}
		su, err := url.Parse(*serverURL)
		if err != nil || (su.Scheme != "http" && su.Scheme != "https") || su.Host == "" {
			return fatalf(env, "--server must be an http:// or https:// URL")
		}
		if tok != "" && su.Scheme == "http" && !isLoopbackHost(su.Hostname()) && !*plainHTTP {
			return fatalf(env, "refusing to send the access token unencrypted to %s; use an https:// URL, or --allow-plain-http if the network path is trusted", su.Host)
		}
		opts.Fleet = &mcpserver.Fleet{Base: strings.TrimRight(*serverURL, "/"), Token: tok}
	} else if *readOnly {
		warnf(env, "--read-only changes nothing without --server: the ad-hoc scan tools never write")
	}
	srv := mcpserver.New(opts)

	if *listen == "" {
		// stdio: stdout is the protocol channel; everything else goes to stderr.
		if *verbose {
			_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon %s: MCP over stdio%s\n", version.Get(), describeMCP(opts))
		}
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
			return fatalf(env, "mcp: %v", err)
		}
		return ExitOK
	}

	k := *key
	if k == "" {
		k = os.Getenv(mcpKeyEnv)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fatalf(env, "--listen must be HOST:PORT: %v", err)
	}
	loopback := isLoopbackHost(host)
	if !loopback && k == "" && !*openNetwork {
		return fatalf(env, "%s is reachable from the network and no key is set; give one with --key (or %s), or accept an open server with --open-network", *listen, mcpKeyEnv)
	}
	if k != "" && len(k) < 16 {
		return fatalf(env, "the key must be at least 16 characters")
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", srv.Handler(mcpserver.HTTPOptions{Key: k}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	hs := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fatalf(env, "listen %s: %v", *listen, err)
	}
	_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon %s: MCP over Streamable HTTP at http://%s/mcp%s\n", version.Get(), ln.Addr(), describeMCP(opts))
	switch {
	case k != "":
		_, _ = fmt.Fprintln(env.Stderr, "clients must send: Authorization: Bearer <key>")
	case !loopback:
		_, _ = fmt.Fprintln(env.Stderr, "WARNING: open to the network without a key (--open-network)")
	}
	go func() {
		<-ctx.Done()
		// ctx is done, so the shutdown gets its own deadline rather than inheriting a cancelled one.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fatalf(env, "mcp: %v", err)
	}
	return ExitOK
}

func describeMCP(o mcpserver.Options) string {
	var parts []string
	if !o.NoScan {
		s := "ad-hoc scans"
		if o.Scan.Guard.Scope != nil {
			s += " within the scope"
		}
		parts = append(parts, s)
	}
	if o.Fleet != nil {
		f := "fleet of " + o.Fleet.Base
		if o.ReadOnly {
			f += " (read-only)"
		}
		parts = append(parts, f)
	}
	if len(parts) == 0 {
		return " (reference catalogues only)"
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// writeDetails prints what --details adds after a verdict, for either protocol.
func writeDetails(w io.Writer, rep any, ev eval.Evaluation) error {
	switch r := rep.(type) {
	case *tlsprobe.Report:
		if err := r.WriteTextWith(w, strengthAnnotations(ev)); err != nil {
			return err
		}
		writeAlgorithms(w, ev)
		writeStandardsDetail(w, ev)
		writeClientsDetail(w, ev)
	case *sshprobe.Report:
		writeSSHDetails(w, r)
		writeStandardsDetail(w, ev)
	default:
		// A stored evaluation has no report here: the standards and clients still have detail.
		writeStandardsDetail(w, ev)
		if ev.Protocol != eval.ProtocolSSH {
			writeClientsDetail(w, ev)
		}
	}
	return nil
}

func mcpUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: cipherhorizon mcp [flags]

Serves CipherHorizon to an assistant over the Model Context Protocol. Without flags it speaks
MCP on stdin/stdout and offers tls_scan and ssh_scan, which run the same probe and judgement as
"tls scan" and "ssh scan", plus the reference catalogues (standards clause by clause, SSH
baselines, simulated clients, the readiness scale) as resources.

  --server URL          also offer the fleet of a running CipherHorizon server through its API:
                        fleet_summary, endpoints_list, endpoint_get, endpoint_add, scan_start,
                        scan_get, findings_list, standards_summary, machines_list, machine_get,
                        inventory_summary, cbom_get. The server's roles apply to the token.
  --token TOKEN         the server's automation token (or `+tokenEnv+`)
  --read-only           leave out endpoint_add and scan_start
  --no-scan             leave out tls_scan and ssh_scan
  --scan-allow NET      limit ad-hoc scans to a network, address or domain (repeatable)
  --allow-loopback      allow ad-hoc scans of this machine
  --listen HOST:PORT    Streamable HTTP at http://HOST:PORT/mcp instead of stdio
  --key KEY             bearer key HTTP clients must send (or `+mcpKeyEnv+`); 16+ characters
  --open-network        allow --listen beyond loopback without a key
  --verbose             log tool calls to stderr

Claude Code:     claude mcp add cipherhorizon -- cipherhorizon mcp --server https://ch.example.net --token TOKEN
Claude Desktop:  {"mcpServers":{"cipherhorizon":{"command":"cipherhorizon","args":["mcp"]}}}
HTTP clients:    cipherhorizon mcp --listen 127.0.0.1:8075 --key KEY   then  http://127.0.0.1:8075/mcp

The assistant is an untrusted caller: it can scan only what the scan scope allows, and change
the server only through the tools you leave in. See docs/mcp.md.
`)
}
