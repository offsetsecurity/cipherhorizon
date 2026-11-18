package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/connector"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/policy"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/workflow"
)

// Planning (PRD-023 M4, M5): what the work adds up to, what work the scans suggest, and the exports
// an auditor reads. Every figure has a definition with its denominator, and what was not observed is
// counted as unknown, never as done or safe.

// workDefinitions say what each figure counts and out of what.
var workDefinitions = map[string]string{
	"open":                 "Work not yet verified, complete or cancelled, out of all work.",
	"overdue":              "Open work whose due date has passed (exceptions excluded), out of open work with a due date.",
	"awaitingApproval":     "Open work whose current stage leads to an approval, out of open work.",
	"awaitingVerification": "Work recorded as changed (executed or reported) that the product has not yet verified, out of open work.",
	"verified":             "Work whose last recorded verification by the product's own scan said verified (stage verified, or complete after verification), out of all work.",
	"completeUnverified":   "Work closed as complete without the product verifying it (the subject cannot be observed, or the workflow does not verify), out of complete work.",
	"exceptions":           "Work in an accepted-risk stage; expired counts those past their end date.",
	"readiness.endpoints":  "TLS endpoints and SSH servers in the inventory.",
	"readiness.scanned":    "Endpoints with at least one completed scan, out of all endpoints. The rest are unknown: never counted as ready or not ready.",
	"readiness.atL3":       "Scanned endpoints whose latest scan reached readiness L3 (hybrid key exchange negotiated) or L4, out of scanned endpoints.",
	"readiness.withWork":   "Scanned endpoints below L3 that have open post-quantum work, out of scanned endpoints below L3.",
}

type workSummary struct {
	Total                int               `json:"total"`
	ByMarker             map[string]int    `json:"byMarker"`
	Open                 int               `json:"open"`
	Overdue              int               `json:"overdue"`
	WithDueDate          int               `json:"withDueDate"`
	AwaitingApproval     int               `json:"awaitingApproval"`
	AwaitingVerification int               `json:"awaitingVerification"`
	Verified             int               `json:"verified"`
	Complete             int               `json:"complete"`
	CompleteUnverified   int               `json:"completeUnverified"`
	Exceptions           int               `json:"exceptions"`
	ExceptionsExpired    int               `json:"exceptionsExpired"`
	Projects             []projectTally    `json:"projects"`
	Readiness            readinessTally    `json:"readiness"`
	Definitions          map[string]string `json:"definitions"`
}

type projectTally struct {
	Project  string `json:"project"`
	Total    int    `json:"total"`
	Open     int    `json:"open"`
	Verified int    `json:"verified"`
	Complete int    `json:"complete"`
	Overdue  int    `json:"overdue"`
}

type readinessTally struct {
	Endpoints int `json:"endpoints"`
	Scanned   int `json:"scanned"`
	AtL3      int `json:"atL3"`
	BelowL3   int `json:"belowL3"`
	// Undetermined: scanned, but the scan could not tell the level. Not counted as below L3.
	Undetermined int `json:"undetermined"`
	WithWork     int `json:"withWork"`
}

func (s *Server) workSummary(w http.ResponseWriter, _ *http.Request) {
	now := s.cfg.Now()
	items, err := s.cfg.Store.ListWork(store.WorkFilter{Limit: 5000})
	if err != nil {
		storeErr(w, err)
		return
	}
	sum := workSummary{ByMarker: map[string]int{}, Projects: []projectTally{}, Definitions: workDefinitions}
	projects := map[string]*projectTally{}
	pqWork := map[int64]bool{}
	for _, it := range items {
		sum.Total++
		sum.ByMarker[it.Marker]++
		finished := workflow.Finished(it.Marker)
		verified := it.Marker == workflow.MarkVerified || (it.Marker == workflow.MarkComplete && wasVerified(it))
		overdue := !finished && it.Marker != workflow.MarkException && it.DueAt != nil && now.After(*it.DueAt)
		if !finished {
			sum.Open++
			if it.DueAt != nil && it.Marker != workflow.MarkException {
				sum.WithDueDate++
			}
			if t, err := workflow.Parse(it.WorkflowJSON); err == nil && slices.ContainsFunc(t.From(it.Stage), func(tr workflow.Transition) bool { return tr.Approval }) {
				sum.AwaitingApproval++
			}
			if workflow.Baseline(it.Marker) {
				sum.AwaitingVerification++
			}
			if it.SubjectKind == workflow.SubjectReadiness && it.AssetID != 0 {
				pqWork[it.AssetID] = true
			}
		}
		if overdue {
			sum.Overdue++
		}
		if verified {
			sum.Verified++
		}
		if it.Marker == workflow.MarkComplete {
			sum.Complete++
			if !wasVerified(it) {
				sum.CompleteUnverified++
			}
		}
		if it.Marker == workflow.MarkException {
			sum.Exceptions++
			if it.ExceptionUntil != nil && now.After(*it.ExceptionUntil) {
				sum.ExceptionsExpired++
			}
		}
		p := projects[it.Project]
		if p == nil {
			p = &projectTally{Project: it.Project}
			projects[it.Project] = p
		}
		p.Total++
		if !finished {
			p.Open++
		}
		if verified {
			p.Verified++
		}
		if it.Marker == workflow.MarkComplete {
			p.Complete++
		}
		if overdue {
			p.Overdue++
		}
	}
	for _, p := range projects {
		sum.Projects = append(sum.Projects, *p)
	}
	sort.Slice(sum.Projects, func(i, j int) bool {
		if (sum.Projects[i].Project == "") != (sum.Projects[j].Project == "") {
			return sum.Projects[j].Project == ""
		}
		return sum.Projects[i].Project < sum.Projects[j].Project
	})

	assets, err := s.cfg.Store.ListAssets("")
	if err != nil {
		storeErr(w, err)
		return
	}
	for _, a := range assets {
		if a.Kind != store.KindTLS && a.Kind != store.KindSSH {
			continue
		}
		sum.Readiness.Endpoints++
		if a.LastDone == nil {
			continue
		}
		sum.Readiness.Scanned++
		l := a.LastDone.ReadinessLevel
		if l == nil || *l < 0 {
			sum.Readiness.Undetermined++
			continue
		}
		if *l >= eval.LevelHybridNeg {
			sum.Readiness.AtL3++
			continue
		}
		sum.Readiness.BelowL3++
		if pqWork[a.ID] {
			sum.Readiness.WithWork++
		}
	}
	writeJSON(w, 200, sum)
}

// ---- suggested work ------------------------------------------------------------------------------

// Suggestion is one piece of work the scans point at, with why and the source it rests on.
type Suggestion struct {
	Key      string         `json:"key"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Reason   string         `json:"reason"`
	Workflow string         `json:"workflow"`
	Subject  workSubjectReq `json:"subject"`
	Link     string         `json:"link"`
	Basis    *suggestBasis  `json:"basis,omitempty"`
}

type suggestBasis struct {
	Milestone string `json:"milestone,omitempty"`
	Document  string `json:"document"`
	Text      string `json:"text"`
	URL       string `json:"url"`
}

func basisOf(milestone string) *suggestBasis {
	c := policy.Default()
	m, ok := c.Milestone(milestone)
	if !ok {
		return nil
	}
	d, _ := c.Document(m.Document)
	return &suggestBasis{Milestone: m.ID, Document: d.Identifier, Text: m.Text, URL: d.URL}
}

const maxSuggestions = 200

func (s *Server) workSuggestions(w http.ResponseWriter, _ *http.Request) {
	out, err := s.suggestions(s.cfg.Now())
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) suggestions(now time.Time) ([]Suggestion, error) {
	items, err := s.cfg.Store.ListWork(store.WorkFilter{Limit: 5000})
	if err != nil {
		return nil, err
	}
	// What already has work (any stage but cancelled): no suggestion for it.
	hasWork := map[string]bool{}
	for _, it := range items {
		if workflow.Finished(it.Marker) {
			continue
		}
		switch it.SubjectKind {
		case workflow.SubjectReadiness:
			hasWork[fmt.Sprintf("readiness:%d", it.AssetID)] = true
		case workflow.SubjectFinding:
			hasWork[fmt.Sprintf("finding:%d:%s", it.AssetID, it.FindingKey)] = true
		case workflow.SubjectCertificate:
			hasWork["certificate:"+it.Certificate] = true
		}
	}
	ls := s.lifecycleSettings()
	var out []Suggestion
	assets, err := s.cfg.Store.ListAssets("")
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		if (a.Kind != store.KindTLS && a.Kind != store.KindSSH) || a.LastDone == nil {
			continue
		}
		link := fmt.Sprintf("#/endpoints/%d", a.ID)
		if a.Kind == store.KindSSH {
			link = fmt.Sprintf("#/ssh/%d", a.ID)
		}
		if l := a.LastDone.ReadinessLevel; l != nil && (*l == eval.LevelExposed || *l == eval.LevelHybridAvail) && !hasWork[fmt.Sprintf("readiness:%d", a.ID)] {
			target := eval.LevelHybridNeg
			reason := "Needs post-quantum key exchange."
			if *l == eval.LevelHybridAvail {
				reason = "It accepts post-quantum key exchange but does not prefer it: the order needs changing."
			}
			sev := "medium"
			if a.LastDone.HNDLExposed {
				sev = "high"
			}
			out = append(out, Suggestion{Key: fmt.Sprintf("readiness:%d", a.ID), Severity: sev, Title: a.Name + ": traffic recorded today could be decrypted later",
				Reason: reason, Workflow: "pq-key-exchange", Link: link, Basis: basisOf("ir8547.key-establishment-deprecated"),
				Subject: workSubjectReq{Kind: workflow.SubjectReadiness, AssetID: a.ID, TargetLevel: &target}})
		}
		findings, err := s.assetFindings(a)
		if err != nil {
			return nil, err
		}
		// One suggestion per endpoint: its worst untracked finding, and how many more wait behind it
		// Seven rows for one server would bury the other endpoints.
		var worst *FlatFinding
		more := 0
		for i := range findings {
			f := findings[i]
			if (f.Severity != "critical" && f.Severity != "high") || f.Category == "certificate" || f.Status != nil ||
				hasWork[fmt.Sprintf("finding:%d:%s", a.ID, f.Key)] {
				continue
			}
			switch {
			case worst == nil:
				worst = &findings[i]
			case f.Severity == "critical" && worst.Severity != "critical":
				worst = &findings[i]
				more++
			default:
				more++
			}
		}
		if worst != nil {
			reason := firstSentence(worst.Remediation, worst.Detail)
			if more > 0 {
				reason += fmt.Sprintf(" %d more serious problem(s) on this server.", more)
			}
			out = append(out, Suggestion{Key: fmt.Sprintf("finding:%d:%s", a.ID, worst.Key), Severity: worst.Severity, Title: worst.Title + " on " + a.Name,
				Reason: reason, Workflow: "tls-configuration-change", Link: link,
				Subject: workSubjectReq{Kind: workflow.SubjectFinding, AssetID: a.ID, FindingKey: worst.Key}})
		}
	}

	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if !c.Current || c.Role() != "end-entity" || hasWork["certificate:"+c.Fingerprint] || !slices.Contains(c.Origins, "scanner") {
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
		days := int(na.Sub(now).Hours() / 24)
		link := "#/certificates/" + c.Fingerprint
		switch {
		case days <= ls.ExpiryWarnDays:
			sev := "medium"
			if days <= ls.ExpiryCriticalDays {
				sev = "high"
			}
			if days < 0 {
				sev = "critical"
			}
			title := fmt.Sprintf("%s: certificate expires in %d days", commonName(name), days)
			if days < 0 {
				title = fmt.Sprintf("%s: certificate expired %d days ago", commonName(name), -days)
			}
			out = append(out, Suggestion{Key: "certificate:" + c.Fingerprint, Severity: sev, Title: title,
				Reason:   fmt.Sprintf("Served by %d endpoint(s).", c.Places),
				Workflow: "certificate-renewal", Link: link, Subject: workSubjectReq{Kind: workflow.SubjectCertificate, Certificate: c.Fingerprint}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRankEv[out[i].Severity] != sevRankEv[out[j].Severity] {
			return sevRankEv[out[i].Severity] < sevRankEv[out[j].Severity]
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > maxSuggestions {
		out = out[:maxSuggestions]
	}
	if out == nil {
		out = []Suggestion{}
	}
	return out, nil
}

func firstSentence(texts ...string) string {
	for _, t := range texts {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if i := strings.Index(t, ". "); i > 0 && i < 300 {
			return t[:i+1]
		}
		if len(t) > 300 {
			return t[:300] + "…"
		}
		return t
	}
	return ""
}

// ---- exports ------------------------------------------------------------------------------------

func verificationStatus(it store.WorkItem) string {
	var v struct {
		Status string `json:"status"`
	}
	if len(it.Verification) == 0 || json.Unmarshal(it.Verification, &v) != nil {
		return ""
	}
	return v.Status
}

func subjectText(it store.WorkItem) string {
	switch it.SubjectKind {
	case workflow.SubjectFinding:
		return fmt.Sprintf("finding %s on asset %d", it.FindingKey, it.AssetID)
	case workflow.SubjectCertificate:
		return "certificate " + it.Certificate
	case workflow.SubjectReadiness:
		lvl := 0
		if it.TargetLevel != nil {
			lvl = *it.TargetLevel
		}
		return fmt.Sprintf("asset %d to L%d", it.AssetID, lvl)
	case workflow.SubjectEndpoint:
		return fmt.Sprintf("asset %d", it.AssetID)
	}
	return fmt.Sprintf("system %d", it.SystemID)
}

func tsOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) workCSV(w http.ResponseWriter, _ *http.Request) {
	items, err := s.cfg.Store.ListWork(store.WorkFilter{Limit: 5000})
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cipherhorizon-work.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "title", "workflow", "stage", "marker", "subject", "owner", "due", "project", "created_by", "created_at",
		"executed_at", "verification", "closed_at", "approvers"})
	for _, it := range items {
		_ = cw.Write([]string{strconv.FormatInt(it.ID, 10), csvSafe(it.Title), it.WorkflowID, it.Stage, it.Marker, csvSafe(subjectText(it)), csvSafe(it.Owner),
			tsOrEmpty(it.DueAt), csvSafe(it.Project), csvSafe(it.CreatedBy), it.CreatedAt.UTC().Format(time.RFC3339), tsOrEmpty(it.ExecutedAt),
			verificationStatus(it), tsOrEmpty(it.ClosedAt), csvSafe(strings.Join(it.Approvers, " "))})
	}
	cw.Flush()
}

// workEvidence is the audit evidence pack: every piece of work with its full history and a fresh
// verification, the definitions of the figures, and the versions of the rules applied.
func (s *Server) workEvidence(w http.ResponseWriter, _ *http.Request) {
	now := s.cfg.Now()
	items, err := s.cfg.Store.ListWork(store.WorkFilter{Limit: 5000})
	if err != nil {
		storeErr(w, err)
		return
	}
	type entry struct {
		Item         workView              `json:"item"`
		Workflow     json.RawMessage       `json:"workflow"`
		History      []store.AuditEntry    `json:"history"`
		Dependencies []store.WorkDep       `json:"dependencies"`
		VerifiedNow  workflow.Verification `json:"verificationNow"`
	}
	out := struct {
		GeneratedAt    time.Time         `json:"generatedAt"`
		Server         string            `json:"server"`
		EvalVersion    string            `json:"evalVersion"`
		CatalogVersion string            `json:"catalogVersion"`
		Definitions    map[string]string `json:"definitions"`
		Note           string            `json:"note"`
		Work           []entry           `json:"work"`
	}{GeneratedAt: now.UTC(), Server: s.cfg.Version, EvalVersion: s.cfg.EvalVersion, CatalogVersion: policy.Default().Version,
		Definitions: workDefinitions, Work: []entry{},
		Note: "verificationNow is computed at export time from the product's own scans after each change; the history is the append-only audit log."}
	for _, it := range items {
		hist, err := s.cfg.Store.Audit(store.WorkObject, it.ID, 500)
		if err != nil {
			storeErr(w, err)
			return
		}
		deps, err := s.cfg.Store.WorkDeps(it.ID)
		if err != nil {
			storeErr(w, err)
			return
		}
		v, _ := s.viewWork(it, now)
		out.Work = append(out.Work, entry{Item: v, Workflow: it.WorkflowJSON, History: hist, Dependencies: deps, VerifiedNow: s.verifyWork(it, now)})
	}
	w.Header().Set("Content-Disposition", `attachment; filename="cipherhorizon-work-evidence.json"`)
	writeJSON(w, 200, out)
}

// ---- certificate lifecycle --------------------------------------------------------------------

func (s *Server) getCertLifecycle(w http.ResponseWriter, r *http.Request) {
	fp := strings.ToLower(r.PathValue("fingerprint"))
	if !fingerprintRE.MatchString(fp) {
		writeErr(w, http.StatusBadRequest, "invalid fingerprint")
		return
	}
	known, err := s.cfg.Store.CertificateKnown(fp)
	if err != nil {
		storeErr(w, err)
		return
	}
	if !known {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	c, _, err := s.cfg.Store.CertificateLifecycle(fp)
	if err != nil {
		storeErr(w, err)
		return
	}
	work, err := s.cfg.Store.ListWork(store.WorkFilter{Certificate: fp, Limit: 50})
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	views := make([]workView, 0, len(work))
	for _, it := range work {
		v, _ := s.viewWork(it, now)
		views = append(views, v)
	}
	writeJSON(w, 200, map[string]any{"lifecycle": c, "work": views, "renewalMethods": store.RenewalMethods})
}

func (s *Server) putCertLifecycle(w http.ResponseWriter, r *http.Request) {
	fp := strings.ToLower(r.PathValue("fingerprint"))
	if !fingerprintRE.MatchString(fp) {
		writeErr(w, http.StatusBadRequest, "invalid fingerprint")
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	var in struct {
		Owner   string `json:"owner"`
		Renewal string `json:"renewal"`
		Notes   string `json:"notes"`
	}
	if !decode(w, r, &in) {
		return
	}
	var c store.CertLifecycle
	var err error
	if c.Owner, err = cleanLine("owner", in.Owner, maxWorkShort); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.Notes, err = cleanText("notes", in.Notes, maxWorkDescription); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Renewal != "" && !slices.Contains(store.RenewalMethods, in.Renewal) {
		writeErr(w, http.StatusBadRequest, "renewal must be one of "+strings.Join(store.RenewalMethods, ", "))
		return
	}
	c.Renewal, c.Fingerprint = in.Renewal, fp
	known, err := s.cfg.Store.CertificateKnown(fp)
	if err != nil {
		storeErr(w, err)
		return
	}
	if !known {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	out, err := s.cfg.Store.SetCertificateLifecycle(c, s.actor(r), reason)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

// ---- integrations --------------------------------------------------------------------------------

func (s *Server) listIntegrations(w http.ResponseWriter, _ *http.Request) {
	ls := s.lifecycleSettings()
	type view struct {
		connector.Descriptor
		Configured bool   `json:"configured"`
		Health     string `json:"health,omitempty"`
	}
	ns, err := s.cfg.Store.Notifications(50)
	if err != nil {
		storeErr(w, err)
		return
	}
	var lastSent, lastFailed *store.Notification
	for i := range ns {
		n := ns[i]
		if n.Status == store.NotifySent && (lastSent == nil || (n.SentAt != nil && lastSent.SentAt != nil && n.SentAt.After(*lastSent.SentAt))) {
			lastSent = &ns[i]
		}
		if n.LastError != "" && lastFailed == nil {
			lastFailed = &ns[i]
		}
	}
	out := []view{}
	for _, d := range connector.Registry() {
		v := view{Descriptor: d}
		switch d.ID {
		case "scanner":
			v.Configured, v.Health = true, "built in"
		case "webhook":
			v.Configured = ls.WebhookURL != ""
			switch {
			case !v.Configured:
				v.Health = "not configured"
			case lastFailed != nil && (lastSent == nil || lastSent.SentAt == nil || !lastFailed.FirstSeen.Before(*lastSent.SentAt)):
				v.Health = "last delivery failed: " + lastFailed.LastError
			case lastSent != nil:
				v.Health = "last delivery " + lastSent.SentAt.UTC().Format(time.RFC3339)
			default:
				v.Health = "configured; nothing sent yet"
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}
