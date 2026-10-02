package app

import (
	"context"
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
	if err := fl.Parse(args); err != nil {
		return ExitFatal
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+*addr+"/api/v1/health", http.NoBody)
	if err != nil {
		return fatalf(env, "healthcheck: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fatalf(env, "healthcheck: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // we only care whether the request succeeded
	if resp.StatusCode != http.StatusOK {
		return fatalf(env, "healthcheck: unexpected status %s", resp.Status)
	}
	return ExitOK
}
