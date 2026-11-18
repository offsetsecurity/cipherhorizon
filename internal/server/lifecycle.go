package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/workflow"
)

// The lifecycle monitor (PRD-023 M2, M5): it looks at the work and the certificates, finds what needs
// a person (work overdue or waiting for an approval, an exception past its end date, verified work
// that no longer holds, certificates expiring, a certificate changed with no work planned for it), and
// sends each event once to the webhook an administrator configured.

// Event kinds.
const (
	EvWorkOverdue          = "work.overdue"
	EvWorkDueSoon          = "work.due-soon"
	EvWorkApproval         = "work.awaiting-approval"
	EvWorkExceptionExpired = "work.exception-expired"
	EvWorkRegressed        = "work.regressed"
	EvCertExpired          = "certificate.expired"
	EvCertExpiring         = "certificate.expiring"
	EvCertUnplanned        = "certificate.unplanned-change"
)

// EventKinds lists every kind with what it means, for the settings page and the documentation.
var EventKinds = []EventKind{
	{EvWorkOverdue, "Work overdue", "A piece of work is past its due date and not finished."},
	{EvWorkDueSoon, "Work due soon", "A piece of work is due within the warning window."},
	{EvWorkApproval, "Approval needed", "A piece of work waits in a stage whose next step is an approval."},
	{EvWorkExceptionExpired, "Exception ended", "An accepted risk has passed its end date."},
	{EvWorkRegressed, "Verified change no longer holds", "A later scan shows again what verified work had fixed."},
	{EvCertExpired, "Certificate expired", "A certificate still served or held has expired."},
	{EvCertExpiring, "Certificate expiring", "A certificate expires within the warning window."},
	{EvCertUnplanned, "Certificate changed without planned work", "An endpoint now serves a different certificate and no work names the old one."},
}

// EventKind is one kind of lifecycle event and what it means.
type EventKind struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	About string `json:"about"`
}

// LifecycleSettings are the monitor's settings. The webhook's signing secret is never stored: the
// setting names the server's environment variable that holds it.
type LifecycleSettings struct {
	ExpiryWarnDays     int      `json:"expiryWarnDays"`
	ExpiryCriticalDays int      `json:"expiryCriticalDays"`
	DueSoonDays        int      `json:"dueSoonDays"`
	WebhookURL         string   `json:"webhookUrl"`
	WebhookFormat      string   `json:"webhookFormat"` // "json" or "chat" ({"text": ...}, as Slack and Teams incoming webhooks accept)
	WebhookSecretEnv   string   `json:"webhookSecretEnv"`
	Events             []string `json:"events"` // empty: every kind
}

const settingLifecycle = "lifecycle"

var defaultLifecycle = LifecycleSettings{ExpiryWarnDays: 30, ExpiryCriticalDays: 7, DueSoonDays: 3, WebhookFormat: "json"}

var envNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

func (s *Server) lifecycleSettings() LifecycleSettings {
	ls := defaultLifecycle
	if raw, err := s.cfg.Store.Setting(settingLifecycle); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &ls)
	}
	if ls.WebhookFormat == "" {
		ls.WebhookFormat = "json"
	}
	return ls
}

func (ls LifecycleSettings) validate() error {
	switch {
	case ls.ExpiryWarnDays < 1 || ls.ExpiryWarnDays > 365:
		return errors.New("the expiry warning must be 1 to 365 days")
	case ls.ExpiryCriticalDays < 0 || ls.ExpiryCriticalDays > ls.ExpiryWarnDays:
		return errors.New("the critical window must be 0 days or more and no longer than the warning window")
	case ls.DueSoonDays < 0 || ls.DueSoonDays > 60:
		return errors.New("due soon must be 0 to 60 days")
	case ls.WebhookFormat != "json" && ls.WebhookFormat != "chat":
		return errors.New(`the webhook format is "json" or "chat"`)
	case ls.WebhookSecretEnv != "" && !envNameRE.MatchString(ls.WebhookSecretEnv):
		return errors.New("the secret is named by an environment variable: capital letters, digits and underscores")
	}
	if ls.WebhookURL != "" {
		u, err := url.Parse(ls.WebhookURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(ls.WebhookURL) > 500 {
			return errors.New("the webhook must be an http or https address without a user name or password in it")
		}
	}
	for _, e := range ls.Events {
		if !slices.ContainsFunc(EventKinds, func(k EventKind) bool { return k.Kind == e }) {
			return fmt.Errorf("%q is not an event kind", e)
		}
	}
	return nil
}

// lifecycleView is the settings as the API shows them: never the secret, only whether it is set.
func (s *Server) lifecycleView() map[string]any {
	ls := s.lifecycleSettings()
	secretSet := ls.WebhookSecretEnv != "" && os.Getenv(ls.WebhookSecretEnv) != ""
	return map[string]any{"settings": ls, "secretSet": secretSet, "kinds": EventKinds}
}

func (s *Server) getLifecycleSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.lifecycleView())
}

func (s *Server) putLifecycleSettings(w http.ResponseWriter, r *http.Request) {
	ls := s.lifecycleSettings()
	if !decode(w, r, &ls) {
		return
	}
	ls.WebhookURL = strings.TrimSpace(ls.WebhookURL)
	if err := ls.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	before := s.lifecycleSettings()
	b, _ := json.Marshal(ls)
	if err := s.cfg.Store.SetSetting(settingLifecycle, string(b)); err != nil {
		storeErr(w, err)
		return
	}
	detail := fmt.Sprintf("expiry warning %d days, critical %d, due soon %d, webhook %s", ls.ExpiryWarnDays, ls.ExpiryCriticalDays, ls.DueSoonDays,
		map[bool]string{true: "set", false: "not set"}[ls.WebhookURL != ""])
	if before.WebhookURL != ls.WebhookURL {
		detail += " (destination changed)"
	}
	if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), "settings", 0, "lifecycle settings changed", detail, ""); err != nil {
		s.log.Warn("recording a settings change failed", "err", err)
	}
	writeJSON(w, 200, s.lifecycleView())
}

// ---- events ---------------------------------------------------------------------------------------

// LifecycleEvent is one thing that needs a person.
type LifecycleEvent struct {
	Key         string    `json:"key"`
	Kind        string    `json:"kind"`
	Severity    string    `json:"severity"` // critical, high, medium, info
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Link        string    `json:"link"` // a path in the web interface
	At          time.Time `json:"at"`
	WorkID      int64     `json:"workId,omitempty"`
	AssetID     int64     `json:"assetId,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
}

var sevRankEv = map[string]int{"critical": 0, "high": 1, "medium": 2, "info": 3}

// lifecycleEvents finds every event as of now.
func (s *Server) lifecycleEvents(now time.Time) ([]LifecycleEvent, error) {
	ls := s.lifecycleSettings()
	var out []LifecycleEvent
	add := func(e LifecycleEvent) {
		e.At = now
		out = append(out, e)
	}
	day := now.UTC().Format(time.DateOnly)

	items, err := s.cfg.Store.ListWork(store.WorkFilter{Limit: 5000})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		link := fmt.Sprintf("#/work/%d", it.ID)
		finished := workflow.Finished(it.Marker)
		if !finished && it.Marker != workflow.MarkException && it.DueAt != nil {
			switch {
			case now.After(*it.DueAt):
				add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%s", EvWorkOverdue, it.ID, it.DueAt.Format(time.DateOnly)), Kind: EvWorkOverdue, Severity: "high",
					Title: fmt.Sprintf("Overdue: %s", it.Title), Detail: fmt.Sprintf("Due %s; owner %s; stage %s.", it.DueAt.Format(time.DateOnly), orNobody(it.Owner), it.Stage),
					Link: link, WorkID: it.ID})
			case it.DueAt.Sub(now) <= time.Duration(ls.DueSoonDays)*24*time.Hour:
				add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%s", EvWorkDueSoon, it.ID, it.DueAt.Format(time.DateOnly)), Kind: EvWorkDueSoon, Severity: "medium",
					Title: fmt.Sprintf("Due %s: %s", it.DueAt.Format(time.DateOnly), it.Title), Detail: fmt.Sprintf("Owner %s; stage %s.", orNobody(it.Owner), it.Stage),
					Link: link, WorkID: it.ID})
			}
		}
		if it.Marker == workflow.MarkException && it.ExceptionUntil != nil && now.After(*it.ExceptionUntil) {
			add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%s", EvWorkExceptionExpired, it.ID, it.ExceptionUntil.Format(time.DateOnly)), Kind: EvWorkExceptionExpired, Severity: "high",
				Title: fmt.Sprintf("Exception ended: %s", it.Title), Detail: fmt.Sprintf("The accepted risk ran until %s. Reopen the work or accept the risk again.", it.ExceptionUntil.Format(time.DateOnly)),
				Link: link, WorkID: it.ID})
		}
		if !finished {
			if t, err := workflow.Parse(it.WorkflowJSON); err == nil && slices.ContainsFunc(t.From(it.Stage), func(tr workflow.Transition) bool { return tr.Approval }) {
				add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%s", EvWorkApproval, it.ID, it.Stage), Kind: EvWorkApproval, Severity: "info",
					Title: fmt.Sprintf("Approval needed: %s", it.Title), Detail: fmt.Sprintf("Requested by %s; someone else must approve.", it.CreatedBy),
					Link: link, WorkID: it.ID})
			}
		}
		if (it.Marker == workflow.MarkVerified || it.Marker == workflow.MarkComplete) && wasVerified(it) {
			if v := s.verifyWork(it, now); v.Status == workflow.NotVerified {
				ev := strings.Join(v.Evidence, ",")
				add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%s", EvWorkRegressed, it.ID, ev), Kind: EvWorkRegressed, Severity: "critical",
					Title: fmt.Sprintf("No longer holds: %s", it.Title), Detail: v.Detail, Link: link, WorkID: it.ID, AssetID: it.AssetID, Certificate: it.Certificate})
			}
		}
	}

	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		return nil, err
	}
	planned, err := s.cfg.Store.WorkCertificates()
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if !c.Current || c.Role() != "end-entity" {
			continue
		}
		na, err := time.Parse(time.RFC3339, c.Attrs["notAfter"])
		if err != nil {
			continue
		}
		name := c.Attrs["subject"]
		if name == "" {
			name = c.Name
		}
		link := "#/certificates/" + c.Fingerprint
		days := int(na.Sub(now).Hours() / 24)
		var work string
		var workID int64
		if id, ok := planned[c.Fingerprint]; ok {
			work, workID = fmt.Sprintf(" Work #%d is open for it.", id), id
		}
		switch {
		case now.After(na):
			add(LifecycleEvent{Key: fmt.Sprintf("%s:%s", EvCertExpired, c.Fingerprint), Kind: EvCertExpired, Severity: "critical",
				Title: "Expired: " + name, Detail: fmt.Sprintf("Expired %s; seen in %d place(s).%s", na.Format(time.DateOnly), c.Places, work),
				Link: link, Certificate: c.Fingerprint, WorkID: workID})
		case days <= ls.ExpiryWarnDays:
			sev, window := "medium", ls.ExpiryWarnDays
			if days <= ls.ExpiryCriticalDays {
				sev, window = "high", ls.ExpiryCriticalDays
			}
			add(LifecycleEvent{Key: fmt.Sprintf("%s:%s:%d", EvCertExpiring, c.Fingerprint, window), Kind: EvCertExpiring, Severity: sev,
				Title: fmt.Sprintf("Expires in %d day(s): %s", days, name), Detail: fmt.Sprintf("Valid until %s; seen in %d place(s).%s", na.Format(time.DateOnly), c.Places, work),
				Link: link, Certificate: c.Fingerprint, WorkID: workID})
		}
	}

	changes, err := s.cfg.Store.RecentLeafChanges(now.Add(-30 * 24 * time.Hour))
	if err != nil {
		return nil, err
	}
	for _, ch := range changes {
		anyPlanned := slices.ContainsFunc(ch.From, func(fp string) bool { _, ok := planned[fp]; return ok })
		if anyPlanned {
			continue
		}
		add(LifecycleEvent{Key: fmt.Sprintf("%s:%d:%d", EvCertUnplanned, ch.AssetID, ch.ToScan), Kind: EvCertUnplanned, Severity: "high",
			Title: "Certificate changed without planned work: " + ch.Name,
			Detail: fmt.Sprintf("Scan %d (%s) found a different certificate from scan %d, and no work names the one it replaced. If the change was expected, record it as work; if not, find out who made it.",
				ch.ToScan, ch.At.Format(time.DateOnly), ch.FromScan),
			Link: fmt.Sprintf("#/endpoints/%d", ch.AssetID), AssetID: ch.AssetID})
	}
	_ = day
	sort.SliceStable(out, func(i, j int) bool {
		if sevRankEv[out[i].Severity] != sevRankEv[out[j].Severity] {
			return sevRankEv[out[i].Severity] < sevRankEv[out[j].Severity]
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

func wasVerified(it store.WorkItem) bool {
	var v struct {
		Status string `json:"status"`
	}
	return len(it.Verification) > 0 && json.Unmarshal(it.Verification, &v) == nil && v.Status == workflow.Verified
}

func orNobody(s string) string {
	if s == "" {
		return "not set"
	}
	return s
}

func (s *Server) listLifecycleEvents(w http.ResponseWriter, _ *http.Request) {
	evs, err := s.lifecycleEvents(s.cfg.Now())
	if err != nil {
		storeErr(w, err)
		return
	}
	if evs == nil {
		evs = []LifecycleEvent{}
	}
	writeJSON(w, 200, evs)
}

func (s *Server) listNotifications(w http.ResponseWriter, _ *http.Request) {
	ns, err := s.cfg.Store.Notifications(200)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, ns)
}

// ---- the monitor and delivery ----------------------------------------------------------------

// MonitorResult is what one pass of the monitor did.
type MonitorResult struct {
	Events    int    `json:"events"`
	New       int    `json:"new"`
	Delivered int    `json:"delivered"`
	Failed    int    `json:"failed"`
	Note      string `json:"note,omitempty"`
}

const maxDeliveryAttempts = 5

// RunMonitor finds the events, records the new ones and delivers what is pending.
func (s *Server) RunMonitor(ctx context.Context) (MonitorResult, error) {
	now := s.cfg.Now()
	evs, err := s.lifecycleEvents(now)
	if err != nil {
		return MonitorResult{}, err
	}
	ls := s.lifecycleSettings()
	res := MonitorResult{Events: len(evs)}
	for _, e := range evs {
		status := store.NotifyPending
		if ls.WebhookURL == "" || (len(ls.Events) > 0 && !slices.Contains(ls.Events, e.Kind)) {
			status = store.NotifyNotSent
		}
		isNew, err := s.cfg.Store.SeeNotification(store.Notification{Key: e.Key, Kind: e.Kind, Severity: e.Severity, Title: e.Title, Detail: e.Detail, Link: e.Link}, status)
		if err != nil {
			return res, err
		}
		if isNew {
			res.New++
		}
	}
	if ls.WebhookURL == "" {
		res.Note = "no webhook is configured: events are listed, not sent"
		return res, nil
	}
	pending, err := s.cfg.Store.PendingNotifications(200)
	if err != nil {
		return res, err
	}
	for _, n := range pending {
		if err := s.deliver(ctx, ls, n); err != nil {
			status := store.NotifyPending
			if n.Attempts+1 >= maxDeliveryAttempts {
				status = store.NotifyFailed
			}
			_ = s.cfg.Store.MarkNotification(n.Key, status, err.Error())
			res.Failed++
			continue
		}
		_ = s.cfg.Store.MarkNotification(n.Key, store.NotifySent, "")
		res.Delivered++
	}
	return res, nil
}

// StartMonitor runs the monitor every interval until ctx is done.
func (s *Server) StartMonitor(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := s.RunMonitor(ctx); err != nil {
					s.log.Warn("the lifecycle monitor failed", "err", err)
				}
			}
		}
	}()
}

// webhookClient dials through the guard (no link-local or cloud-metadata address, loopback only when
// the server allows it), follows no redirect and gives up after ten seconds. The scan scope does not
// apply: a webhook is a destination an administrator chose, not a scan target.
func (s *Server) webhookClient() *http.Client {
	g := Guard{AllowLoopback: s.cfg.Guard.AllowLoopback}
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: g.Control}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, Proxy: nil}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// webhookBody is what a notification looks like on the wire.
func webhookBody(ls LifecycleSettings, n store.Notification, base string) ([]byte, error) {
	link := n.Link
	if base != "" && strings.HasPrefix(link, "#/") {
		link = strings.TrimRight(base, "/") + "/" + link
	}
	if ls.WebhookFormat == "chat" {
		return json.Marshal(map[string]string{"text": fmt.Sprintf("[%s] %s\n%s\n%s", n.Severity, n.Title, n.Detail, link)})
	}
	return json.Marshal(map[string]any{"source": "cipherhorizon", "event": n.Kind, "key": n.Key, "severity": n.Severity,
		"title": n.Title, "detail": n.Detail, "link": link, "firstSeen": n.FirstSeen.UTC().Format(time.RFC3339)})
}

func (s *Server) deliver(ctx context.Context, ls LifecycleSettings, n store.Notification) error {
	body, err := webhookBody(ls, n, s.cfg.PublicURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ls.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CipherHorizon/"+s.cfg.Version)
	req.Header.Set("X-CipherHorizon-Event", n.Kind)
	if ls.WebhookSecretEnv != "" {
		if secret := os.Getenv(ls.WebhookSecretEnv); secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			req.Header.Set("X-CipherHorizon-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	resp, err := s.webhookClient().Do(req)
	if err != nil {
		// The error names the address, never the body or the secret.
		return fmt.Errorf("the webhook could not be reached: %s", cleanDialError(err))
	}
	defer resp.Body.Close() //nolint:errcheck // response drained below
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the webhook answered %d", resp.StatusCode)
	}
	return nil
}

func cleanDialError(err error) string {
	msg := err.Error()
	if errors.Is(err, ErrBlocked) {
		return "the address is not allowed (" + msg[strings.LastIndex(msg, ":")+1:] + ")"
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// runMonitorNow runs one pass on request (administrators): the settings page's "Check now".
func (s *Server) runMonitorNow(w http.ResponseWriter, r *http.Request) {
	res, err := s.RunMonitor(r.Context())
	if err != nil {
		storeErr(w, err)
		return
	}
	detail := fmt.Sprintf("%d events, %d new, %d delivered, %d failed", res.Events, res.New, res.Delivered, res.Failed)
	if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), "settings", 0, "lifecycle check run", detail, ""); err != nil {
		s.log.Warn("recording a lifecycle check failed", "err", err)
	}
	writeJSON(w, 200, res)
}

// testWebhook sends one test message to the configured webhook (administrators).
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	ls := s.lifecycleSettings()
	if ls.WebhookURL == "" {
		writeErr(w, http.StatusConflict, "no webhook is configured")
		return
	}
	n := store.Notification{Key: "test:" + s.cfg.Now().UTC().Format(time.RFC3339), Kind: "test", Severity: "info",
		Title: "CipherHorizon test message", Detail: "If you can read this, lifecycle notifications reach this destination.", Link: "#/work",
		FirstSeen: s.cfg.Now()}
	if err := s.deliver(r.Context(), ls, n); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), "settings", 0, "test notification sent", "", ""); err != nil {
		s.log.Warn("recording a test notification failed", "err", err)
	}
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

// adminOnly refuses anyone but an administrator (the local operator with sign-in off is one).
func (s *Server) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p, _ := principalOf(r); p.Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, "only an administrator can do this")
			return
		}
		h(w, r)
	}
}
