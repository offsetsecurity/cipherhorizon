package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// importCmd implements "cipherhorizon import": send a third-party CycloneDX CBOM (1.6 or 1.7) to a
// running server. The subject is the operator's decision, given on the command line: the
// document's own claim about what it describes decides nothing (SECARCH-001 SR-04).
func importCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("import", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	server := fl.String("server", "http://127.0.0.1:8080", "base URL of the CipherHorizon server")
	token := fl.String("token", "", "access token (or "+tokenEnv+"); the environment keeps it out of the process list")
	system := fl.Int64("system", 0, "id of the existing system the document describes")
	newSystem := fl.String("new-system", "", "name of a new system the document describes")
	if err := fl.Parse(args); err != nil {
		return ExitFatal
	}
	if fl.NArg() != 1 || (*system == 0) == (*newSystem == "") {
		_, _ = fmt.Fprint(env.Stderr, `usage: cipherhorizon import [--server URL] [--token TOKEN] (--system ID | --new-system NAME) FILE|-

Imports a CycloneDX 1.6 or 1.7 CBOM made by another tool (CBOMkit, CBOM-Lens, cdxgen, ...). You say which
system it describes; the document's own claim about its subject is recorded and never used to place it.
`)
		return ExitFatal
	}
	tok := *token
	if tok == "" {
		tok = os.Getenv(tokenEnv)
	}
	var raw []byte
	var err error
	if fl.Arg(0) == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 33<<20))
	} else {
		raw, err = os.ReadFile(fl.Arg(0))
	}
	if err != nil {
		return fatalf(env, "reading the document: %v", err)
	}

	q := url.Values{}
	if *system != 0 {
		q.Set("system", strconv.FormatInt(*system, 10))
	} else {
		q.Set("newSystem", *newSystem)
	}
	u := strings.TrimRight(*server, "/") + "/api/v1/imports?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(raw)))
	if err != nil {
		return fatalf(env, "%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "cipherhorizon")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fatalf(env, "cannot reach %s: %v", *server, err)
	}
	defer resp.Body.Close() //nolint:errcheck // exiting
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 300 {
		var e struct {
			Error    string `json:"error"`
			Stage    string `json:"stage"`
			Problems []struct {
				Path    string `json:"path"`
				Message string `json:"message"`
			} `json:"problems"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		_, _ = fmt.Fprintf(env.Stderr, "cipherhorizon: the server refused the document (%d): %s\n", resp.StatusCode, oneLine(msg, 300))
		for _, p := range e.Problems {
			_, _ = fmt.Fprintf(env.Stderr, "  %s: %s\n", oneLine(p.Path, 80), oneLine(p.Message, 200))
		}
		return ExitFatal
	}
	var out struct {
		Import struct {
			ID             int64          `json:"id"`
			Observations   int            `json:"observations"`
			SystemID       int64          `json:"systemId"`
			SystemName     string         `json:"systemName"`
			NotInterpreted map[string]int `json:"notInterpreted"`
		} `json:"import"`
		ProfileLabel string `json:"profileLabel"`
		Duplicate    bool   `json:"duplicate"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fatalf(env, "the server's reply was not understood")
	}
	if out.Duplicate {
		_, _ = fmt.Fprintf(env.Stdout, "already imported (import %d) for system %d %q: nothing changed\n", out.Import.ID, out.Import.SystemID, oneLine(out.Import.SystemName, 80))
		return ExitOK
	}
	_, _ = fmt.Fprintf(env.Stdout, "imported as %s: import %d, %d observations, system %d %q\n", oneLine(out.ProfileLabel, 80), out.Import.ID, out.Import.Observations, out.Import.SystemID, oneLine(out.Import.SystemName, 80))
	for k, n := range out.Import.NotInterpreted {
		_, _ = fmt.Fprintf(env.Stdout, "  not interpreted: %s (%d)\n", oneLine(k, 160), n)
	}
	return ExitOK
}

// oneLine makes server text safe to print to a terminal: control characters become '?', and it is shortened.
func oneLine(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
