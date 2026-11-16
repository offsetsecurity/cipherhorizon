package namefind

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CTSearcher finds names in Certificate Transparency logs. A search tells the service which
// domain is being asked about, so the caller only supplies one when the operator turned it on.
type CTSearcher interface {
	// Name is the service asked, for the report.
	Name() string
	// Search returns every name in certificates issued for the domain or a name under it.
	// Wildcard names are returned as they are ("*.example.com").
	Search(ctx context.Context, domain string) ([]string, error)
}

// CrtSh searches crt.sh, Sectigo's public search over the logs. It is free and needs no key; it
// limits each address to a few requests a minute and can time out on a very large domain.
type CrtSh struct {
	// Client makes the request (default: a client with a two-minute timeout).
	Client *http.Client
	// URL replaces https://crt.sh/ (tests).
	URL string
}

// crtShMaxBody bounds the answer: a domain with a million certificates is still under it.
const crtShMaxBody = 256 << 20

// Name implements CTSearcher.
func (CrtSh) Name() string { return "crt.sh" }

// Search implements CTSearcher.
func (c CrtSh) Search(ctx context.Context, domain string) ([]string, error) {
	base := c.URL
	if base == "" {
		base = "https://crt.sh/"
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	u := base + "?output=json&q=" + url.QueryEscape("%."+domain)
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
			}
		}
		names, retry, err := c.once(ctx, client, u)
		if err == nil {
			return names, nil
		}
		last = err
		if !retry {
			break
		}
	}
	return nil, last
}

// retryDelay is how long to wait before the one retry; a variable so tests need not wait.
var retryDelay = 15 * time.Second

func (CrtSh) once(ctx context.Context, client *http.Client, u string) (names []string, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cipherhorizon")
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, fmt.Errorf("status %d", resp.StatusCode)
	}
	// The answer is one JSON array with an object per certificate. It is read one object at a
	// time, so a large answer is never held whole.
	dec := json.NewDecoder(io.LimitReader(resp.Body, crtShMaxBody))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, false, fmt.Errorf("the answer is not a JSON list")
	}
	seen := map[string]bool{}
	for dec.More() {
		var row struct {
			CommonName string `json:"common_name"`
			NameValue  string `json:"name_value"`
		}
		if err := dec.Decode(&row); err != nil {
			return nil, false, fmt.Errorf("the answer could not be read: %w", err)
		}
		for _, n := range append(strings.Split(row.NameValue, "\n"), row.CommonName) {
			n = strings.ToLower(strings.TrimSpace(n))
			if n != "" && !seen[n] && !strings.ContainsAny(n, " @") {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names, false, nil
}
