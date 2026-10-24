package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/auth"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
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
	return isLoopbackHost(host)
}

// isLoopbackHost reports whether a host name or address is this machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseProxies reads --trusted-proxy values: an IP address or a CIDR block each.
func parseProxies(vals []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if ip := net.ParseIP(v); ip != nil {
			bits := 8 * len(ip.To16())
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an IP address nor a CIDR block", v)
		}
		out = append(out, n)
	}
	return out, nil
}

// Where the server listens, when no flag says (PRD-009 REQ-PORT-2): a container, a service
// or a shell can move it without editing the command line.
const (
	addrEnv     = "CIPHERHORIZON_ADDR"
	portEnv     = "CIPHERHORIZON_PORT"
	defaultHost = "127.0.0.1"
	defaultPort = 8080
)

// listenAddr works out the address to listen on from --addr and --port (flagged says which were
// given) and, for what was not given, the environment, then the default 127.0.0.1:8080.
// --addr may be a host alone; --port then supplies the port. Both saying a port is an error,
// since one of them would be silently ignored.
func listenAddr(addr string, port int, addrFlagged, portFlagged bool, getenv func(string) string) (string, error) {
	addrFrom, portFrom := "--addr", "--port"
	if !addrFlagged {
		addr, addrFrom = strings.TrimSpace(getenv(addrEnv)), addrEnv
	}
	if !portFlagged {
		port, portFrom = -1, portEnv
		if v := strings.TrimSpace(getenv(portEnv)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return "", fmt.Errorf("%s=%q is not a port number (1 to 65535, or 0 for any free port)", portEnv, v)
			}
			port = n
		}
	}
	if port != -1 && (port < 0 || port > 65535) {
		return "", fmt.Errorf("%s %d is not a port number (1 to 65535, or 0 for any free port)", portFrom, port)
	}
	host, addrPort := addr, ""
	if addr != "" {
		if h, p, err := net.SplitHostPort(addr); err == nil {
			host, addrPort = h, p
		} else if strings.Count(addr, ":") == 1 || (strings.HasPrefix(addr, "[") && strings.Contains(addr, "]:")) {
			return "", fmt.Errorf("%s %q: %w", addrFrom, addr, err)
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	switch {
	case addrPort != "" && port != -1 && portFlagged == addrFlagged:
		// Both from flags, or both from the environment: neither outranks the other.
		return "", fmt.Errorf("%s %q already names a port; give the port once: with %s, or in %s", addrFrom, addr, portFrom, addrFrom)
	case addrPort != "" && port != -1 && !portFlagged:
		port = -1 // a flag outranks the environment: --addr host:port wins over CIPHERHORIZON_PORT
	case addrPort != "" && port != -1:
		addrPort = "" // --port outranks CIPHERHORIZON_ADDR's port
	}
	if addr == "" {
		host = defaultHost
	}
	switch {
	case port != -1:
		addrPort = strconv.Itoa(port)
	case addrPort == "":
		addrPort = strconv.Itoa(defaultPort)
	}
	return net.JoinHostPort(host, addrPort), nil
}

// busyPortMessage says what to do when the port is taken (PRD-009 REQ-PORT-3).
func busyPortMessage(addr string) string {
	host, p, err := net.SplitHostPort(addr)
	n, convErr := strconv.Atoi(p)
	if err != nil || convErr != nil || n <= 0 {
		return fmt.Sprintf("%s is already in use (another CipherHorizon, or another program). Choose another port with --port", addr)
	}
	next := n + 1
	if next > 65535 {
		next = n - 1
	}
	if host == "" {
		host = "every interface"
	}
	return fmt.Sprintf("port %d is already in use on %s (another CipherHorizon, or another program). Start on another port with --port %d, "+
		"or stop what is using it", n, host, next)
}

// serveCmd implements "cipherhorizon serve": the web UI, the API and the scan runner.
func serveCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	addr := fl.String("addr", "", "address to listen on: host:port, or a host alone with --port (default 127.0.0.1:8080, or "+addrEnv+" and "+portEnv+")")
	port := fl.Int("port", -1, "port to listen on, keeping the host of --addr (or set "+portEnv+"); 0 picks any free port")
	dbPath := fl.String("db", "", dbFlagHelp())
	migrateMode := fl.String("migrate", "auto", "what to do with a database made by an older version: auto (upgrade it at start, after a backup) "+
		"or refuse (stop and say so; upgrade it yourself with cipherhorizon db migrate)")
	token := fl.String("token", "", "an automation token: scripts and tools may call the API with it as a bearer token, acting as an analyst (or set "+tokenEnv+")")
	signInMode := fl.String("sign-in", "auto", "require sign-in: auto (off until turned on in Settings; on if accounts already exist), "+
		"on (always; the first start prints a setup code for the administrator) or off (never)")
	login := fl.Bool("login", false, "same as --sign-in on")
	noLogin := fl.Bool("no-login", false, "same as --sign-in off")
	openNetwork := fl.Bool("open-network", false, "allow listening beyond loopback while sign-in is off: anyone who reaches the port can use "+
		"the server, including to scan. Without it, such a server must require sign-in")
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
	var allowedHosts, trustedProxies, scanAllow stringList
	fl.Var(&scanAllow, "scan-allow", "limit what can be scanned to this network (CIDR), address or domain and the names under it, "+
		"e.g. 10.20.0.0/16 or example.com (repeatable). Without it, anything routable can be scanned except loopback, link-local "+
		"and cloud-metadata addresses")
	fl.Var(&allowedHosts, "allowed-host", "extra Host header accepted when no token is set (repeatable)")
	fl.Var(&trustedProxies, "trusted-proxy", "address or CIDR of a reverse proxy in front of this server whose X-Forwarded-For names the real client, "+
		"for sign-in rate limits and the sign-in log (repeatable). Without it every request is attributed to its direct peer")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() > 0 {
		return fatalf(env, "unexpected argument %q", fl.Arg(0))
	}
	set := map[string]bool{}
	fl.Visit(func(f *flag.Flag) { set[f.Name] = true })
	listen, err := listenAddr(*addr, *port, set["addr"], set["port"], os.Getenv)
	if err != nil {
		return fatalf(env, "%v", err)
	}
	*addr = listen
	if *token == "" {
		*token = os.Getenv(tokenEnv)
	}
	switch {
	case *login && *noLogin:
		return fatalf(env, "--login and --no-login contradict each other")
	case *login:
		*signInMode = "on"
	case *noLogin:
		*signInMode = "off"
	}
	if *signInMode != "auto" && *signInMode != "on" && *signInMode != "off" {
		return fatalf(env, "--sign-in must be auto, on or off")
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
	case !loopback && !useTLS && !*plainHTTP:
		return fatalf(env, "refusing to listen on %q over plain HTTP: passwords and session cookies would cross the network unencrypted. "+
			"Serve HTTPS with --tls-cert and --tls-key, or, if a TLS-terminating proxy is in front, add --plain-http", *addr)
	case *sessionIdle < time.Minute || *sessionMax < *sessionIdle:
		return fatalf(env, "--session-idle must be at least a minute and --session-max at least --session-idle")
	}
	proxies, err := parseProxies(trustedProxies)
	if err != nil {
		return fatalf(env, "--trusted-proxy: %v", err)
	}
	var tlsCfg *tls.Config
	if useTLS {
		pair, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fatalf(env, "loading --tls-cert/--tls-key: %v", err)
		}
		// TLS 1.2 and 1.3 only; Go's default curve preferences offer X25519MLKEM768 first.
		tlsCfg = server.TLSConfig([]tls.Certificate{pair})
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

	if *dbPath, err = resolveDB(*dbPath, env); err != nil {
		return fatalf(env, "choosing the database: %v", err)
	}
	// Exclusive: one server per database, and no other version upgrading it underneath this one.
	opts := store.OpenOptions{Exclusive: true}
	switch *migrateMode {
	case "auto":
	case "refuse":
		opts.Migrate = store.MigrateRefuse
	default:
		return fatalf(env, "--migrate must be auto or refuse")
	}
	st, err := store.OpenWith(*dbPath, opts)
	if err != nil {
		return fatalf(env, "opening the database: %v", err)
	}
	defer st.Close() //nolint:errcheck // nothing useful to do on close at exit

	log := slog.New(slog.NewTextHandler(env.Stderr, nil))
	st.SetLogger(log)
	if n, err := st.FailInterrupted(); err != nil {
		return fatalf(env, "recovering interrupted scans: %v", err)
	} else if n > 0 {
		log.Warn("marked scans interrupted by the last shutdown as failed", "count", n)
	}

	// First run: until an administrator exists, a one-time code printed here (and only here)
	// lets whoever can read the server's log create one. Someone who merely reaches the port cannot.
	signInOn := *signInMode == "on"
	if *signInMode == "auto" {
		v, err := st.Setting(store.SettingSignIn)
		if err != nil {
			return fatalf(env, "reading settings: %v", err)
		}
		signInOn = v == "on"
	}
	if !loopback && !signInOn && !*openNetwork {
		return fatalf(env, "refusing to listen on %q without sign-in: anyone who reaches it could use it, including to scan. "+
			"Require sign-in with --sign-in on, or accept an open server with --open-network", *addr)
	}
	setupCode, setupExpires := "", time.Time{}
	if signInOn {
		n, err := st.CountUsers()
		if err != nil {
			return fatalf(env, "reading accounts: %v", err)
		}
		if n == 0 {
			if setupCode, err = auth.NewSetupCode(); err != nil {
				return fatalf(env, "making the setup code: %v", err)
			}
			// A half-installed server must not stay claimable for ever by whoever later reads its
			// log (PRD-007 REQ-TR-3).
			setupExpires = time.Now().Add(24 * time.Hour)
		}
	}

	scope, err := server.ParseScope(scanAllow)
	if err != nil {
		return fatalf(env, "%v", err)
	}
	guard := server.Guard{AllowLoopback: *allowLoopback, Scope: scope}
	runner := server.NewRunner(st, guard, server.RunnerOptions{
		Workers:  *workers,
		Scan:     tlsprobe.Options{Timeout: *timeout, Concurrency: *concurrency, HTTPChecks: *httpChecks},
		CABundle: bundle,
		Log:      log,
	})
	if n := runner.ReevaluateOutdated(); n > 0 {
		log.Info("re-evaluated the latest results with the current rules", "endpoints", n, "rules", eval.Version)
	}
	srv := server.New(server.Config{
		Store: st, Runner: runner, Guard: guard,
		Token: *token, AllowedHosts: allowedHosts, TrustedProxies: proxies,
		RequireLogin: *signInMode == "on", ForbidLogin: *signInMode == "off", AllowOpen: loopback || *openNetwork, SetupCode: setupCode, SetupCodeExpires: setupExpires, SecureCookies: useTLS,
		SessionIdle: *sessionIdle, SessionMax: *sessionMax,
		Version: version.Version, EvalVersion: eval.Version,
		RegistryRetrieved:  registry.GroupsRetrieved,
		MaxConcurrentScans: *workers,
		Log:                log,
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		if isAddrInUse(err) {
			return fatalf(env, "%s", busyPortMessage(*addr))
		}
		return fatalf(env, "listening on %s: %v", *addr, err)
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// A TLS scanner aimed at this server (including this product's own) makes hundreds of
		// handshakes the server rightly refuses; each would be a log line. Keep every other error.
		ErrorLog: stdlog.New(handshakeNoiseFilter{w: env.Stderr}, "", stdlog.LstdFlags),
	}

	runCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	runner.Start(runCtx)

	_, _ = fmt.Fprint(env.Stderr, serveNotice)
	if scope.Empty() {
		_, _ = fmt.Fprintln(env.Stderr, "scan scope: anything routable (limit it with --scan-allow)")
	} else {
		_, _ = fmt.Fprintf(env.Stderr, "scan scope: only %s\n", strings.Join(scope.Entries(), ", "))
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	mode := "sign-in required"
	if !signInOn {
		mode = "no sign-in; turn it on in Settings"
		if *signInMode == "off" {
			mode = "no sign-in (--sign-in off)"
		}
	}
	if *token != "" {
		mode += ", automation token accepted"
	}
	_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon %s: UI and API on %s://%s (%s), database %s\n", version.Version, scheme, ln.Addr(), mode, *dbPath)
	if setupCode != "" {
		_, _ = fmt.Fprintf(env.Stderr, "\nfirst run: no account exists yet. Open %s://%s and create the administrator with this one-time setup code:\n\n    %s\n\n"+
			"(it is shown only here; it stops working once the administrator exists, or at %s; restart the server for a new one)\n\n",
			scheme, ln.Addr(), setupCode, setupExpires.Format("2006-01-02 15:04 MST"))
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

// handshakeNoiseFilter drops the http.Server's "TLS handshake error" lines and passes the rest.
type handshakeNoiseFilter struct{ w io.Writer }

func (f handshakeNoiseFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil
	}
	return f.w.Write(p)
}
