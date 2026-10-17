package app

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"os"
	"time"
)

// loopbackFor is the address to reach a listener on this machine: a wildcard host (every
// interface) is reached on loopback.
func loopbackFor(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// healthcheckCmd is a small, fast probe of this server's own health route, for a container
// orchestrator's HEALTHCHECK: the release image is distroless (no shell, no curl, no wget), so
// the binary checks itself instead of shelling out to a tool that is not there. It needs no
// token — /api/v1/health is the one route that answers without one — and prints nothing on
// success; a failure says why, for `docker inspect`'s health log.
func healthcheckCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	addr := fl.String("addr", "", "this server's own listen address (default: as serve works it out, from "+addrEnv+" and "+portEnv+", else 127.0.0.1:8080)")
	port := fl.Int("port", -1, "this server's port, keeping the host of --addr (or "+portEnv+")")
	useTLS := fl.Bool("tls", false, "the server serves HTTPS (--tls-cert): probe over HTTPS. The certificate is not verified: "+
		"this only asks the local process whether it is up, and sends nothing secret")
	if err := fl.Parse(args); err != nil {
		return ExitFatal
	}
	set := map[string]bool{}
	fl.Visit(func(f *flag.Flag) { set[f.Name] = true })
	// The same rules as serve, so a server moved to another port with CIPHERHORIZON_PORT is
	// still found without the health command being edited (PRD-009 REQ-PORT-2).
	target, err := listenAddr(*addr, *port, set["addr"], set["port"], os.Getenv)
	if err != nil {
		return fatalf(env, "healthcheck: %v", err)
	}
	target = loopbackFor(target)
	scheme, client := "http", http.DefaultClient
	if *useTLS {
		scheme = "https"
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // a liveness probe of our own loopback listener
		}}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+"/api/v1/health", http.NoBody)
	if err != nil {
		return fatalf(env, "healthcheck: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fatalf(env, "healthcheck: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // we only care whether the request succeeded
	if resp.StatusCode != http.StatusOK {
		return fatalf(env, "healthcheck: unexpected status %s", resp.Status)
	}
	return ExitOK
}
