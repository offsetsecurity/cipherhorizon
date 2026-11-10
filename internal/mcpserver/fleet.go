package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// Fleet is the CipherHorizon server the fleet tools talk to, through its HTTP API.
type Fleet struct {
	// Base is the server's URL, e.g. https://cipherhorizon.example.net.
	Base string
	// Token is the automation token (serve --token), sent as a bearer token. Empty when the
	// credentials come with each call (serve --mcp forwards the caller's own).
	Token string
	// Client makes the requests; nil means a default with a timeout. serve --mcp sets a Client
	// whose Transport calls the server in-process.
	Client *http.Client
}

// credentialsKey carries the caller's own Authorization and Cookie headers through the context,
// for a Fleet mounted inside the server (REQ-MCP-9).
type credentialsKey struct{}

// WithCredentials returns ctx carrying the headers that identify the caller to the server.
func WithCredentials(ctx context.Context, h http.Header) context.Context {
	c := http.Header{}
	for _, k := range []string{"Authorization", "Cookie"} {
		if v := h.Get(k); v != "" {
			c.Set(k, v)
		}
	}
	return context.WithValue(ctx, credentialsKey{}, c)
}

// apiError is the server's refusal, with the status so the model can tell "not found" from "forbidden".
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	switch e.Status {
	case http.StatusNotFound:
		return "not found: " + e.Message
	case http.StatusUnauthorized:
		return "the CipherHorizon server refused the credentials (" + e.Message + "); check the token"
	case http.StatusForbidden:
		return "the CipherHorizon server refused this (" + e.Message + ")"
	}
	return fmt.Sprintf("the CipherHorizon server answered %d: %s", e.Status, e.Message)
}

const maxAPIBody = 32 << 20 // a host's CBOM or the merged inventory can run to tens of MiB

// call makes one API request and decodes the JSON answer into out (nil: discard).
func (f *Fleet) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := strings.TrimRight(f.Base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "cipherhorizon") // the server's cross-site guard
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	if c, ok := ctx.Value(credentialsKey{}).(http.Header); ok {
		for k, v := range c {
			req.Header[k] = v
		}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the CipherHorizon server at %s: %w", f.Base, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return fmt.Errorf("reading the server's answer: %w", err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
			if len(e.Error) > 200 {
				e.Error = e.Error[:200]
			}
		}
		return &apiError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("the server's answer was not the JSON expected: %w", err)
	}
	return nil
}

// ---- shared shapes ----------------------------------------------------------------------------

// Page bounds a list: the model asks for a window and is told how much there is.
type Page struct {
	Limit  int `json:"limit,omitempty" jsonschema:"items to return (default 50, at most 200)"`
	Offset int `json:"offset,omitempty" jsonschema:"items to skip"`
}

func (p Page) window(n int) (lo, hi, limit int) {
	limit = p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	lo = p.Offset
	if lo < 0 {
		lo = 0
	}
	if lo > n {
		lo = n
	}
	hi = lo + limit
	if hi > n {
		hi = n
	}
	return lo, hi, limit
}

// ListResult is a window onto a list.
type ListResult[T any] struct {
	Items     []T  `json:"items"`
	Total     int  `json:"total"`
	Offset    int  `json:"offset"`
	Limit     int  `json:"limit"`
	Truncated bool `json:"truncated" jsonschema:"more items exist after this window"`
}

func page[T any](items []T, p Page) ListResult[T] {
	lo, hi, limit := p.window(len(items))
	out := items[lo:hi]
	if out == nil {
		out = []T{}
	}
	return ListResult[T]{Items: out, Total: len(items), Offset: lo, Limit: limit, Truncated: hi < len(items)}
}

// scanSummary mirrors store.ScanSummary as the API returns it.
type scanSummary struct {
	ID             int64             `json:"id"`
	AssetID        int64             `json:"assetId"`
	Status         string            `json:"status" jsonschema:"queued, running, done, failed or canceled"`
	Trigger        string            `json:"trigger,omitempty"`
	Stage          string            `json:"stage,omitempty"`
	ProgressPct    int               `json:"progressPct"`
	QueuedAt       time.Time         `json:"queuedAt"`
	StartedAt      *time.Time        `json:"startedAt,omitempty"`
	FinishedAt     *time.Time        `json:"finishedAt,omitempty"`
	Error          string            `json:"error,omitempty"`
	Band           string            `json:"band,omitempty" jsonschema:"TLS hygiene band"`
	Score          int               `json:"score" jsonschema:"TLS hygiene score, -1 when not rated"`
	ReadinessLevel *int              `json:"readinessLevel,omitempty"`
	HNDLExposed    bool              `json:"hndlExposed"`
	Critical       int               `json:"critical"`
	High           int               `json:"high"`
	Medium         int               `json:"medium"`
	Low            int               `json:"low"`
	Standards      map[string]string `json:"standards,omitempty" jsonschema:"standard id to verdict"`
}

// endpointView is an asset as the API returns it, trimmed to what the model needs.
type endpointView struct {
	ID              int64        `json:"id"`
	Kind            string       `json:"kind" jsonschema:"tls-endpoint, ssh-endpoint or host"`
	Protocol        string       `json:"protocol,omitempty" jsonschema:"tls or ssh"`
	Name            string       `json:"name"`
	Address         string       `json:"address"`
	Host            string       `json:"host"`
	Port            int          `json:"port"`
	StartTLSUsed    string       `json:"starttlsUsed,omitempty"`
	Tags            []string     `json:"tags"`
	Notes           string       `json:"notes,omitempty"`
	IntervalSeconds int          `json:"intervalSeconds" jsonschema:"scheduled scan interval; 0 is manual only"`
	SystemID        int64        `json:"systemId,omitempty"`
	Latest          *scanSummary `json:"latest,omitempty" jsonschema:"the most recent scan, running or not"`
	LastDone        *scanSummary `json:"lastDone,omitempty" jsonschema:"the most recent completed scan: the current verdict"`
}

// ---- inputs ----------------------------------------------------------------------------------------

// EndpointsListInput filters the endpoint list.
type EndpointsListInput struct {
	Protocol string `json:"protocol,omitempty" jsonschema:"tls or ssh; empty for both"`
	Tag      string `json:"tag,omitempty" jsonschema:"only endpoints carrying this tag"`
	Query    string `json:"query,omitempty" jsonschema:"only endpoints whose name or address contains this text"`
	// Only narrows by state.
	Only string `json:"only,omitempty" jsonschema:"all (default), not-ready (readiness below L3), failing (hygiene below 55 or a critical finding), hndl-exposed, never-scanned"`
	Page
}

// EndpointInput names one endpoint.
type EndpointInput struct {
	ID int64 `json:"id" jsonschema:"the endpoint's id, from endpoints_list"`
}

// EndpointGetInput names one endpoint and how much of its latest verdict to return.
type EndpointGetInput struct {
	ID     int64  `json:"id" jsonschema:"the endpoint's id, from endpoints_list"`
	Detail string `json:"detail,omitempty" jsonschema:"verdict (default), findings or full, as for tls_scan"`
}

// EndpointAddInput adds an endpoint.
type EndpointAddInput struct {
	Target   string   `json:"target" jsonschema:"host, host:port or URL. ssh:// names an SSH server; https://, smtp:// and the other STARTTLS schemes a TLS one. Port 22 is SSH unless protocol says otherwise"`
	Protocol string   `json:"protocol,omitempty" jsonschema:"auto (default), tls or ssh"`
	Name     string   `json:"name,omitempty" jsonschema:"a display name; the address when empty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Scan     bool     `json:"scan,omitempty" jsonschema:"also queue a first scan"`
}

// ScanStartInput starts stored scans.
type ScanStartInput struct {
	EndpointIDs []int64 `json:"endpointIds,omitempty" jsonschema:"the endpoints to scan"`
	Tag         string  `json:"tag,omitempty" jsonschema:"scan every endpoint carrying this tag instead"`
	All         bool    `json:"all,omitempty" jsonschema:"scan every endpoint; prefer a tag or ids"`
}

// ScanGetInput names one stored scan.
type ScanGetInput struct {
	ID     int64  `json:"id" jsonschema:"the scan's id, from scan_start or an endpoint's latest scan"`
	Detail string `json:"detail,omitempty" jsonschema:"status (default: the scan's state and progress), verdict, findings or full once the scan is done"`
}

// FindingsListInput filters the fleet's findings.
type FindingsListInput struct {
	Severity string `json:"severity,omitempty" jsonschema:"critical, high, medium, low, info, or vulnerable (quantum-vulnerable algorithms on hosts)"`
	Status   string `json:"status,omitempty" jsonschema:"new (no status set), acknowledged or accepted-risk; empty for every finding"`
	Protocol string `json:"protocol,omitempty" jsonschema:"tls, ssh or host; empty for all"`
	Page
}

// MachinesListInput filters the host inventory's machines.
type MachinesListInput struct {
	Query string `json:"query,omitempty" jsonschema:"only machines whose name contains this text"`
	Page
}

// CBOMInput names what to export.
type CBOMInput struct {
	ScanID int64 `json:"scanId,omitempty" jsonschema:"a completed stored scan: the CBOM of what that scan observed"`
	// Fleet-wide inventory when nothing is named.
	Inventory bool `json:"inventory,omitempty" jsonschema:"the merged inventory CBOM of every machine instead"`
}

// ---- outputs ----------------------------------------------------------------------------------------

// FleetSummary is what the Overview shows, as the API returns it, passed through.
type FleetSummary = map[string]any

// EndpointResult is one endpoint with, when asked, its latest verdict.
type EndpointResult struct {
	Endpoint endpointView     `json:"endpoint"`
	Verdict  *ScanResult      `json:"verdict,omitempty" jsonschema:"the latest completed scan judged, as tls_scan or ssh_scan would return it"`
	History  []map[string]any `json:"history,omitempty" jsonschema:"recent completed scans, newest first (at most 10): when, level, score, counts"`
	ScanURL  string           `json:"reportUrl,omitempty" jsonschema:"the report page in the web interface"`
}

// ScanStartResult says what was queued.
type ScanStartResult struct {
	Queued        int           `json:"queued"`
	AlreadyActive int           `json:"alreadyActive"`
	Missing       int           `json:"missing"`
	Scans         []scanSummary `json:"scans"`
	Note          string        `json:"note"`
}

// ScanGetResult is one stored scan.
type ScanGetResult struct {
	Scan    scanSummary `json:"scan"`
	Asset   endpointRef `json:"endpoint"`
	Events  []string    `json:"events,omitempty" jsonschema:"the scan's log, oldest first"`
	Verdict *ScanResult `json:"verdict,omitempty"`
}

type endpointRef struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// FlatFinding is one finding across the fleet, as the API returns it.
type FlatFinding struct {
	AssetID     int64  `json:"assetId"`
	AssetName   string `json:"assetName"`
	AssetKind   string `json:"assetKind"`
	Key         string `json:"key"`
	Title       string `json:"title"`
	Detail      string `json:"detail,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Category    string `json:"category,omitempty"`
	Class       string `json:"class,omitempty" jsonschema:"post-quantum class for host findings"`
	Remediation string `json:"remediation,omitempty"`
	Status      *struct {
		Status string `json:"status"`
		Note   string `json:"note,omitempty"`
	} `json:"status,omitempty"`
}

// CBOMResult carries a CycloneDX document.
type CBOMResult struct {
	MIMEType string `json:"mimeType"`
	Size     int    `json:"size"`
	Document any    `json:"document,omitempty"`
	Note     string `json:"note,omitempty"`
}

// ---- tools ---------------------------------------------------------------------------------------------

func (s *Server) addFleetTools() {
	f := s.opts.Fleet
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "fleet_summary",
		Title: "Fleet summary",
		Description: "The state of everything the CipherHorizon server tracks: endpoints by readiness level and hygiene band, " +
			"findings by severity, scans running, the readiness trend. Start here for any question about the fleet.",
		Annotations: readOnly("Fleet summary", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
		Days int `json:"days,omitempty" jsonschema:"days of trend to include (default 30)"`
	}) (*mcp.CallToolResult, FleetSummary, error) {
		q := url.Values{}
		if in.Days > 0 {
			q.Set("days", strconv.Itoa(in.Days))
		}
		var out FleetSummary
		if err := f.call(ctx, http.MethodGet, "/api/v1/summary", q, nil, &out); err != nil {
			return failf[FleetSummary]("%v", err)
		}
		return nil, out, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "endpoints_list",
		Title: "List endpoints",
		Description: "The TLS and SSH endpoints the server tracks, each with its latest completed scan's readiness level, hygiene " +
			"score, finding counts and standards verdicts. Filter by protocol, tag, text or state; page with limit and offset. " +
			"Use endpoint_get for one endpoint's full verdict.",
		Annotations: readOnly("List endpoints", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in EndpointsListInput) (*mcp.CallToolResult, ListResult[endpointView], error) {
		var all []endpointView
		q := url.Values{"kind": {"endpoint"}}
		switch strings.ToLower(in.Protocol) {
		case "tls":
			q.Set("kind", "tls-endpoint")
		case "ssh":
			q.Set("kind", "ssh-endpoint")
		case "":
		default:
			return failf[ListResult[endpointView]](`protocol must be "tls", "ssh" or empty`)
		}
		if err := f.call(ctx, http.MethodGet, "/api/v1/assets", q, nil, &all); err != nil {
			return failf[ListResult[endpointView]]("%v", err)
		}
		var keep []endpointView
		query := strings.ToLower(strings.TrimSpace(in.Query))
		for _, e := range all {
			if in.Tag != "" && !hasTag(e.Tags, in.Tag) {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(e.Name), query) && !strings.Contains(strings.ToLower(e.Address), query) {
				continue
			}
			ok, err := matchesOnly(e, in.Only)
			if err != nil {
				return failf[ListResult[endpointView]]("%v", err)
			}
			if ok {
				if e.Latest != nil && e.LastDone != nil && e.Latest.ID == e.LastDone.ID {
					e.Latest = nil // the same scan twice says nothing more
				}
				keep = append(keep, e)
			}
		}
		return nil, page(keep, in.Page), nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "endpoint_get",
		Title: "Get an endpoint",
		Description: "One tracked endpoint with its latest completed scan judged: readiness, hygiene, standards, what to fix first " +
			"(detail verdict), every finding and clause not met (findings), or the whole evaluation (full). Also its recent history. " +
			"Nothing is scanned; use scan_start to refresh.",
		Annotations: readOnly("Get an endpoint", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in EndpointGetInput) (*mcp.CallToolResult, EndpointResult, error) {
		detail, err := detailLevel(in.Detail)
		if err != nil {
			return failf[EndpointResult]("%v", err)
		}
		var e endpointView
		if err := f.call(ctx, http.MethodGet, "/api/v1/assets/"+strconv.FormatInt(in.ID, 10), nil, nil, &e); err != nil {
			return failf[EndpointResult]("%v", err)
		}
		out := EndpointResult{Endpoint: e}
		var hist []map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/assets/"+strconv.FormatInt(in.ID, 10)+"/history", url.Values{"limit": {"10"}}, nil, &hist); err == nil {
			out.History = hist
		}
		if e.LastDone != nil {
			v, err := s.storedVerdict(ctx, e.LastDone.ID, e.Protocol, e.Address, detail)
			if err != nil {
				return failf[EndpointResult]("%v", err)
			}
			out.Verdict = v
			out.ScanURL = strings.TrimRight(f.Base, "/") + "/#/assets/" + strconv.FormatInt(e.ID, 10)
		}
		text := e.Name + " (" + e.Address + ")"
		if out.Verdict != nil {
			text = s.verdictTextFor(out.Verdict, e.Address)
		} else {
			text += ": never scanned"
		}
		return textResult(text, out)
	})

	if !s.opts.ReadOnly {
		mcp.AddTool(s.Server, &mcp.Tool{
			Name:  "endpoint_add",
			Title: "Add an endpoint",
			Description: "Record a TLS or SSH endpoint on the CipherHorizon server so it is tracked, scanned on a schedule and " +
				"reported on. Optionally queue its first scan. Adding the same address twice is refused. Do this only when the " +
				"user wants the endpoint tracked; for a one-off question use tls_scan or ssh_scan.",
			Annotations: additive("Add an endpoint", false),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in EndpointAddInput) (*mcp.CallToolResult, EndpointResult, error) {
			body := map[string]any{"target": strings.TrimSpace(in.Target), "protocol": in.Protocol, "name": in.Name, "tags": in.Tags, "notes": in.Notes}
			var e endpointView
			if err := f.call(ctx, http.MethodPost, "/api/v1/assets", nil, body, &e); err != nil {
				return failf[EndpointResult]("%v", err)
			}
			out := EndpointResult{Endpoint: e}
			text := "Added " + e.Name + " (" + e.Address + ") as endpoint " + strconv.FormatInt(e.ID, 10) + "."
			if in.Scan {
				var sc struct {
					Scan scanSummary `json:"scan"`
				}
				if err := f.call(ctx, http.MethodPost, "/api/v1/assets/"+strconv.FormatInt(e.ID, 10)+"/scan", nil, map[string]any{}, &sc); err != nil {
					return failf[EndpointResult]("added, but the scan could not be queued: %v", err)
				}
				out.Endpoint.Latest = &sc.Scan
				text += fmt.Sprintf(" Scan %d queued; follow it with scan_get.", sc.Scan.ID)
			}
			return textResult(text, out)
		})

		mcp.AddTool(s.Server, &mcp.Tool{
			Name:  "scan_start",
			Title: "Start stored scans",
			Description: "Queue a scan of tracked endpoints on the CipherHorizon server (by ids, by tag, or all). The server scans " +
				"in the background and stores the result; follow each scan with scan_get until its status is done or failed " +
				"(a TLS scan takes 5–40 s, SSH under 5 s). An endpoint already being scanned is not queued twice.",
			Annotations: additive("Start stored scans", true),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in ScanStartInput) (*mcp.CallToolResult, ScanStartResult, error) {
			if len(in.EndpointIDs) == 0 && in.Tag == "" && !in.All {
				return failf[ScanStartResult]("name endpointIds, a tag, or all")
			}
			var out ScanStartResult
			if err := f.call(ctx, http.MethodPost, "/api/v1/scans", nil, map[string]any{"assetIds": in.EndpointIDs, "tag": in.Tag, "all": in.All}, &out); err != nil {
				return failf[ScanStartResult]("%v", err)
			}
			out.Note = "Poll scan_get with each scan id until status is done or failed."
			return nil, out, nil
		})
	}

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "scan_get",
		Title: "Get a stored scan",
		Description: "One stored scan's status and progress and, once done, its verdict (detail verdict, findings or full). " +
			"Poll it after scan_start; a scan that is queued or running has no verdict yet.",
		Annotations: readOnly("Get a stored scan", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ScanGetInput) (*mcp.CallToolResult, ScanGetResult, error) {
		detail := strings.ToLower(strings.TrimSpace(in.Detail))
		if detail != "" && detail != "status" {
			if _, err := detailLevel(detail); err != nil {
				return failf[ScanGetResult](`detail must be "status", "verdict", "findings" or "full"`)
			}
		}
		var raw struct {
			Scan   scanSummary `json:"scan"`
			Events []struct {
				Message string `json:"message"`
			} `json:"events"`
			Asset endpointRef `json:"asset"`
		}
		if err := f.call(ctx, http.MethodGet, "/api/v1/scans/"+strconv.FormatInt(in.ID, 10), nil, nil, &raw); err != nil {
			return failf[ScanGetResult]("%v", err)
		}
		out := ScanGetResult{Scan: raw.Scan, Asset: raw.Asset}
		for _, e := range raw.Events {
			out.Events = append(out.Events, e.Message)
		}
		text := fmt.Sprintf("Scan %d of %s: %s", raw.Scan.ID, raw.Asset.Address, raw.Scan.Status)
		if raw.Scan.Status == "running" {
			text += fmt.Sprintf(" (%s, %d%%)", raw.Scan.Stage, raw.Scan.ProgressPct)
		}
		if raw.Scan.Error != "" {
			text += ": " + raw.Scan.Error
		}
		if raw.Scan.Status == "done" && detail != "" && detail != "status" {
			protocol := "tls"
			var e endpointView
			if err := f.call(ctx, http.MethodGet, "/api/v1/assets/"+strconv.FormatInt(raw.Scan.AssetID, 10), nil, nil, &e); err == nil && e.Protocol != "" {
				protocol = e.Protocol
			}
			v, err := s.storedVerdict(ctx, raw.Scan.ID, protocol, raw.Asset.Address, detail)
			if err != nil {
				return failf[ScanGetResult]("%v", err)
			}
			out.Verdict = v
			text = s.verdictTextFor(v, raw.Asset.Address)
		}
		return textResult(text, out)
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "findings_list",
		Title: "List findings",
		Description: "Every open finding across the fleet, worst first: TLS and SSH findings from the latest scans and " +
			"quantum-vulnerable algorithms on inventoried machines. Filter by severity, status or protocol; page with limit and offset.",
		Annotations: readOnly("List findings", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in FindingsListInput) (*mcp.CallToolResult, ListResult[FlatFinding], error) {
		q := url.Values{}
		if in.Severity != "" {
			q.Set("severity", strings.ToLower(in.Severity))
		}
		if in.Status != "" {
			q.Set("status", in.Status)
		}
		switch strings.ToLower(in.Protocol) {
		case "tls":
			q.Set("kind", "tls-endpoint")
		case "ssh":
			q.Set("kind", "ssh-endpoint")
		case "host", "hosts", "machine", "machines":
			q.Set("kind", "host")
		case "":
		default:
			return failf[ListResult[FlatFinding]](`protocol must be "tls", "ssh", "host" or empty`)
		}
		var all []FlatFinding
		if err := f.call(ctx, http.MethodGet, "/api/v1/findings", q, nil, &all); err != nil {
			return failf[ListResult[FlatFinding]]("%v", err)
		}
		return nil, page(all, in.Page), nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "standards_summary",
		Title: "Standards across the fleet",
		Description: "For each published standard the program carries: how many tracked endpoints meet it, do not, or could not " +
			"be assessed, with the endpoint ids in each group. Use endpoint_get with detail findings to see which clauses fail.",
		Annotations: readOnly("Standards across the fleet", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		var out map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/standards/summary", nil, nil, &out); err != nil {
			return failf[map[string]any]("%v", err)
		}
		return nil, out, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "machines_list",
		Title: "List inventoried machines",
		Description: "The machines whose cryptographic inventory (a CycloneDX CBOM from the collector script) the server holds: " +
			"name, operating system, when it last reported, how many quantum-vulnerable and quantum-safe algorithms it carries.",
		Annotations: readOnly("List inventoried machines", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in MachinesListInput) (*mcp.CallToolResult, ListResult[map[string]any], error) {
		var all []map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/hosts", nil, nil, &all); err != nil {
			return failf[ListResult[map[string]any]]("%v", err)
		}
		query := strings.ToLower(strings.TrimSpace(in.Query))
		var keep []map[string]any
		for _, h := range all {
			if query != "" {
				name, _ := h["name"].(string)
				host, _ := h["hostname"].(string)
				if !strings.Contains(strings.ToLower(name), query) && !strings.Contains(strings.ToLower(host), query) {
					continue
				}
			}
			delete(h, "summary") // the per-machine algorithm tables: machine_get returns them
			keep = append(keep, h)
		}
		return nil, page(keep, in.Page), nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "machine_get",
		Title: "Get a machine",
		Description: "One inventoried machine: its operating system, the cryptographic libraries, tools and runtimes found, every " +
			"algorithm with its post-quantum status and where it was found, and the history of its reports.",
		Annotations: readOnly("Get a machine", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in EndpointInput) (*mcp.CallToolResult, map[string]any, error) {
		var out map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/hosts/"+strconv.FormatInt(in.ID, 10), nil, nil, &out); err != nil {
			return failf[map[string]any]("%v", err)
		}
		if raw, note := compactJSON(out); raw == nil {
			return failf[map[string]any]("%s", note)
		}
		return nil, out, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "inventory_summary",
		Title: "Inventory summary",
		Description: "Counts across every inventoried machine: algorithms (quantum-vulnerable and quantum-safe), libraries, " +
			"protocols, certificates, keys and machines. The host inventory's front page in numbers.",
		Annotations: readOnly("Inventory summary", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		var out map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/inventory/summary", nil, nil, &out); err != nil {
			return failf[map[string]any]("%v", err)
		}
		var dash map[string]any
		if err := f.call(ctx, http.MethodGet, "/api/v1/inventory/dashboard", nil, nil, &dash); err == nil {
			out["dashboard"] = dash
		}
		return nil, out, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:  "cbom_get",
		Title: "Get a CBOM",
		Description: "A CycloneDX CBOM (JSON): what one stored scan observed on an endpoint (scanId), or the merged inventory of " +
			"every machine (inventory). Documents over 200 KiB are not returned inline; the result then says so.",
		Annotations: readOnly("Get a CBOM", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CBOMInput) (*mcp.CallToolResult, CBOMResult, error) {
		var path string
		switch {
		case in.ScanID > 0 && !in.Inventory:
			path = "/api/v1/scans/" + strconv.FormatInt(in.ScanID, 10) + "/cbom"
		case in.Inventory && in.ScanID == 0:
			path = "/api/v1/inventory/cbom"
		default:
			return failf[CBOMResult]("name exactly one of scanId or inventory")
		}
		var doc json.RawMessage
		if err := f.call(ctx, http.MethodGet, path, nil, nil, &doc); err != nil {
			return failf[CBOMResult]("%v", err)
		}
		out := CBOMResult{MIMEType: "application/vnd.cyclonedx+json", Size: len(doc)}
		if len(doc) > maxJSON {
			out.Note = fmt.Sprintf("the document is %d KiB; download it from %s%s instead", len(doc)>>10, strings.TrimRight(f.Base, "/"), path)
			return textResult(out.Note, out)
		}
		var parsed any
		if err := json.Unmarshal(doc, &parsed); err != nil {
			return failf[CBOMResult]("the server's CBOM was not JSON: %v", err)
		}
		out.Document = parsed
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(doc)}}}, out, nil
	})
}

// storedVerdict fetches a completed scan's evaluation (and, for full detail, its report) and
// renders it as the scan tools would.
func (s *Server) storedVerdict(ctx context.Context, scanID int64, protocol, address, detail string) (*ScanResult, error) {
	var ev eval.Evaluation
	if err := s.opts.Fleet.call(ctx, http.MethodGet, "/api/v1/scans/"+strconv.FormatInt(scanID, 10)+"/evaluation", nil, nil, &ev); err != nil {
		return nil, err
	}
	res := &ScanResult{Target: address, Protocol: protocol, Scanned: true}
	fill(res, ev, detail)
	if protocol == "ssh" {
		if ev.Baseline != nil {
			b := ev.Baseline
			res.Baseline = &BaselineView{ID: b.Baseline, Title: b.Title, Judged: b.Judged, Meets: b.Meets, Reason: b.Reason, Changes: len(b.Changes)}
			if detail != DetailVerdict {
				for _, c := range b.Changes {
					res.Changes = append(res.Changes, c.Text)
				}
				res.SSHDConfig = b.SSHDConfig
			}
		}
	} else {
		res.Hygiene = &HygieneView{Score: ev.Hygiene.Score, Band: ev.Hygiene.Band}
		if cs := eval.SummariseClients(ev.Clients); cs != nil {
			res.Clients = &ClientsView{Connect: cs.Connect, Fail: cs.Fail, PQ: cs.PQ, NoFS: cs.NoFS}
		}
	}
	res.text = s.verdictText(address, nil, ev, DetailVerdict)
	return res, nil
}

// verdictTextFor is the text half of a stored verdict.
func (s *Server) verdictTextFor(v *ScanResult, address string) string {
	if v.text != "" {
		return v.text
	}
	return address
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// matchesOnly applies the "only" filter of endpoints_list.
func matchesOnly(e endpointView, only string) (bool, error) {
	d := e.LastDone
	switch strings.ToLower(strings.TrimSpace(only)) {
	case "", "all":
		return true, nil
	case "never-scanned":
		return d == nil, nil
	case "not-ready":
		return d != nil && d.ReadinessLevel != nil && *d.ReadinessLevel < 3, nil
	case "failing":
		return d != nil && ((d.Score >= 0 && d.Score < 55) || d.Critical > 0), nil
	case "hndl-exposed":
		return d != nil && d.HNDLExposed, nil
	}
	return false, errors.New(`only must be "all", "not-ready", "failing", "hndl-exposed" or "never-scanned"`)
}
