package app

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"time"
)

// healthcheckCmd is a small, fast probe of this server's own health route, for a container
// orchestrator's HEALTHCHECK: the release image is distroless (no shell, no curl, no wget), so
// the binary checks itself instead of shelling out to a tool that is not there. It needs no
// token — /api/v1/health is the one route that answers without one — and prints nothing on
// success; a failure says why, for `docker inspect`'s health log.
func healthcheckCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	addr := fl.String("addr", "127.0.0.1:8080", "this server's own listen address")
	useTLS := fl.Bool("tls", false, "the server serves HTTPS (--tls-cert): probe over HTTPS. The certificate is not verified: "+
		"this only asks the local process whether it is up, and sends nothing secret")
	if err := fl.Parse(args); err != nil {
		return ExitFatal
	}
	scheme, client := "http", http.DefaultClient
	if *useTLS {
		scheme = "https"
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // a liveness probe of our own loopback listener
		}}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+*addr+"/api/v1/health", http.NoBody)
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
