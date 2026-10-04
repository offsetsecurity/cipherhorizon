package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/auth"
	"github.com/example/cipherhorizon/internal/eval"
	"github.com/example/cipherhorizon/internal/server"
	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
	"github.com/example/cipherhorizon/internal/tlsprobe/registry"
	"github.com/example/cipherhorizon/internal/version"
)

const serveNotice = `notice: the web UI lets its users make this machine connect to the endpoints they add,
        with a few hundred short TLS handshakes each. Scan only systems you own or are authorised to test.
`

// tokenEnv is where the access token may be supplied instead of a flag, so it
// does not show up in the process list.
const tokenEnv = "CIPHERHORIZON_TOKEN"

// minTokenLen is the shortest access token accepted. It is a shared secret on a
// network-facing API, so a guessable one defeats the point of having it.
const minTokenLen = 16

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

// Set implements flag.Value: each occurrence of the flag adds one value.
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// isLoopbackAddr reports whether a listen address binds only the loopback
// interface. An empty host (":8080") binds every interface and is not loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serveCmd implements "cipherhorizon serve": the web UI, the API and the scan runner.
func serveCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	addr := fl.String("addr", "127.0.0.1:8080", "address to listen on")
	dbPath := fl.String("db", "cipherhorizon.db", "SQLite database file (created if missing)")
	token := fl.String("token", "", "an automation token: scripts and tools may call the API with it as a bearer token, acting as an analyst (or set "+tokenEnv+")")
	noLogin := fl.Bool("no-login", false, "run without accounts or sign-in: one local operator, loopback only (the behaviour before accounts)")
	tlsCert := fl.String("tls-cert", "", "serve HTTPS with this PEM certificate (chain) file; needs --tls-key")
	tlsKey := fl.String("tls-key", "", "the private key for --tls-cert")
	plainHTTP := fl.Bool("plain-http", false, "allow plain HTTP on a non-loopback address because a TLS-terminating proxy sits in front "+
		"(the session cookie is marked Secure when the proxy sends X-Forwarded-Proto: https), or because the port is published only on this host")
	sessionIdle := fl.Duration("session-idle", 30*time.Minute, "sign a browser out after this long without activity")
	sessionMax := fl.Duration("session-max", 12*time.Hour, "sign a browser out after this long in any case")
	allowLoopback := fl.Bool("allow-loopback", false, "let scans target loopback addresses (for testing)")
	workers := fl.Int("max-concurrent-scans", 2, "scans that may run at once")
	timeout := fl.Duration("timeout", 8*time.Second, "per-connection timeout during a scan")
	concurrency := fl.Int("concurrency", 4, "connections in flight to one target at once")
	httpChecks := fl.Bool("http-checks", true, "after each scan's handshake, send one plain HTTP GET / and read the Strict-Transport-Security header. "+
		"This is the only check that sends anything beyond a TLS handshake: one real HTTP request to every scanned target, read for headers only. "+
		"On by default, server-wide; --http-checks=false turns it off")
	caBundle := fl.String("ca-bundle", "", "PEM file of private CA certificates every scan is also judged against (\"trusted by your CA bundle\"). "+
		"Certificates only: a file containing a private-key block is refused")
	var allowedHosts stringList
	fl.Var(&allowedHosts, "allowed-host", "extra Host header accepted when no token is set (repeatable)")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() > 0 {
		return fatalf(env, "unexpected argument %q", fl.Arg(0))
	}
	if *token == "" {
		*token = os.Getenv(tokenEnv)
	}
	if *token != "" && len(*token) < minTokenLen {
		return fatalf(env, "the access token is too short (%d characters; at least %d are required). "+
			"Generate one with:  openssl rand -hex 24   (or, on Windows, in PowerShell:  -join ((1..24) | %% { '{0:x2}' -f (Get-Random -Max 256) }))",
			len(*token), minTokenLen)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fatalf(env, "--tls-cert and --tls-key go together")
	}
	useTLS := *tlsCert != ""
	loopback := isLoopbackAddr(*addr)
	switch {
	case *noLogin && !loopback:
		return fatalf(env, "refusing to listen on %q without sign-in (--no-login): it is reachable from the network. "+
			"Drop --no-login (accounts are on by default), or bind 127.0.0.1", *addr)
	case !*noLogin && !loopback && !useTLS && !*plainHTTP:
		return fatalf(env, "refusing to listen on %q over plain HTTP: passwords and session cookies would cross the network unencrypted. "+
			"Serve HTTPS with --tls-cert and --tls-key, or, if a TLS-terminating proxy is in front, add --plain-http", *addr)
	case *sessionIdle < time.Minute || *sessionMax < *sessionIdle:
		return fatalf(env, "--session-idle must be at least a minute and --session-max at least --session-idle")
	}
	var tlsCfg *tls.Config
	if useTLS {
		pair, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fatalf(env, "loading --tls-cert/--tls-key: %v", err)
		}
		// TLS 1.2 and 1.3 only; Go's default curve preferences offer X25519MLKEM768 first.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}

	var bundle []server.AnchorCert
	if *caBundle != "" {
		fi, err := os.Stat(*caBundle)
		if err != nil {
			return fatalf(env, "--ca-bundle: %v", err)
		}
		if fi.Size() > 1<<20 {
			return fatalf(env, "--ca-bundle: the file is larger than 1 MiB")
		}
		data, err := os.ReadFile(*caBundle)
		if err != nil {
			return fatalf(env, "--ca-bundle: %v", err)
		}
		if bundle, err = server.ParseAnchors(data, 500); err != nil {
			return fatalf(env, "--ca-bundle %s: %v", *caBundle, err)
		}
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return fatalf(env, "opening the database: %v", err)
	}
	defer st.Close() //nolint:errcheck // nothing useful to do on close at exit

	log := slog.New(slog.NewTextHandler(env.Stderr, nil))
	if n, err := st.FailInterrupted(); err != nil {
		return fatalf(env, "recovering interrupted scans: %v", err)
	} else if n > 0 {
		log.Warn("marked scans interrupted by the last shutdown as failed", "count", n)
	}

	// First run: until an administrator exists, a one-time code printed here (and only here)
	// lets whoever can read the server's log create one. Someone who merely reaches the port cannot.
	setupCode := ""
	if !*noLogin {
		n, err := st.CountUsers()
		if err != nil {
			return fatalf(env, "reading accounts: %v", err)
		}
		if n == 0 {
			if setupCode, err = auth.NewSetupCode(); err != nil {
				return fatalf(env, "making the setup code: %v", err)
			}
		}
	}

	guard := server.Guard{AllowLoopback: *allowLoopback}
	runner := server.NewRunner(st, guard, server.RunnerOptions{
		Workers:  *workers,
		Scan:     tlsprobe.Options{Timeout: *timeout, Concurrency: *concurrency, HTTPChecks: *httpChecks},
		CABundle: bundle,
	})
	if n := runner.ReevaluateOutdated(); n > 0 {
		log.Info("re-evaluated the latest results with the current rules", "endpoints", n, "rules", eval.Version)
	}
	srv := server.New(server.Config{
		Store: st, Runner: runner, Guard: guard,
		Token: *token, AllowedHosts: allowedHosts,
		RequireLogin: !*noLogin, SetupCode: setupCode, SecureCookies: useTLS,
		SessionIdle: *sessionIdle, SessionMax: *sessionMax,
		Version: version.Version, EvalVersion: eval.Version,
		RegistryRetrieved:  registry.GroupsRetrieved,
		MaxConcurrentScans: *workers,
		Log:                log,
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fatalf(env, "listening on %s: %v", *addr, err)
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	runCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	runner.Start(runCtx)

	_, _ = fmt.Fprint(env.Stderr, serveNotice)
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	mode := "sign-in required"
	if *noLogin {
		mode = "no sign-in (loopback only)"
	}
	if *token != "" {
		mode += ", automation token accepted"
	}
	_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon %s: UI and API on %s://%s (%s), database %s\n", version.Version, scheme, ln.Addr(), mode, *dbPath)
	if setupCode != "" {
		_, _ = fmt.Fprintf(env.Stderr, "\nfirst run: no account exists yet. Open %s://%s and create the administrator with this one-time setup code:\n\n    %s\n\n"+
			"(it is shown only here, and stops working once the administrator exists)\n\n", scheme, ln.Addr(), setupCode)
	} else {
		_, _ = fmt.Fprintf(env.Stderr, "next: open %s://%s in a browser.\n", scheme, ln.Addr())
	}

	errc := make(chan error, 1)
	go func() {
		if useTLS {
			errc <- httpSrv.ServeTLS(ln, "", "")
			return
		}
		errc <- httpSrv.Serve(ln)
	}()

	select {
	case err := <-errc:
		stopRunner()
		runner.Wait()
		return fatalf(env, "server stopped: %v", err)
	case <-ctx.Done():
	}
	_, _ = fmt.Fprintln(env.Stderr, "shutting down…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	stopRunner()
	runner.Wait()
	return ExitOK
}
