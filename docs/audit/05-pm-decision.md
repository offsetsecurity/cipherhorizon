# 05 · PM review and decision

**Role:** Product manager. **Inputs:** `01-security-audit.md`, `02-usability-audit.md`, `03-gap-analysis.md`,
`04-ui-direction.md`. **Rule applied:** approve what makes the first release safer or lets a new person succeed
alone; defer what needs something the team does not have (a machine, a certificate, the owner's identity) or a decision
that is not yet made; never approve work that cannot be verified in this environment and then call it done.

## Decisions

### Security

| ID | Decision | Acceptance criterion |
|---|---|---|
| SEC-01 | **Approve** | A new database and its `-wal`/`-shm` have mode `0600` on POSIX; an existing file is tightened at start; a test proves it on POSIX and skips on Windows. |
| SEC-02 | **Approve** | The collector's output file is `0600`. |
| SEC-03 | **Approve** | Tokens shorter than 16 characters are refused at start with a message that says how to make one; failed authentication is logged without the value and delayed; tests cover both. |
| SEC-04 | **Approve** | `0.0.0.0/8` and NAT64-embedded metadata addresses are refused; table test. |
| SEC-05 | **Approve** | A host name with a control character or invalid UTF-8 is refused with a 400. |
| SEC-06 | **Defer** | Needs a per-instance storage budget decision. Recorded as a known limit in `SECURITY.md`. |
| SEC-07 | **Approve** | `Permissions-Policy` sent on every response. |
| SEC-08 | **Approve** | Every `actions/checkout` sets `persist-credentials: false`. |
| SEC-09 | **Defer** | Multi-user model is a roadmap item; stated in `SECURITY.md`. |
| SEC-10 | **Blocked on owner** | Stays in the release checklist; not faked. |

### Usability and UI

| ID | Decision | Acceptance criterion |
|---|---|---|
| UX-01 | **Approve (P0)** | First run shows two labelled paths; each leads to a working action; covered by the browser journey. |
| UX-02 | **Approve (P0)** | The Hosts page shows the exact collector command with a copy button, before and after the first upload. |
| UX-03 | **Approve (P0)** | A host page shows operating system, privilege level, coverage and not-seen list read from the uploaded CBOM; a standard-user run shows the elevation nudge; an older CBOM without the properties degrades to "not recorded", never to an error. |
| UX-04 | **Approve** | Algorithm rows show verdict and one line; rationale and citations open on demand; duplicates in "provided by" are collapsed. |
| UX-05 | **Approve** | "Components", operating system and coverage badge on the list. |
| UX-06 | **Approve** | Six KPI cards fit two rows of three at desktop width and two per row on a phone. |
| UX-07 | **Approve** | The harvest-now-decrypt-later card explains itself. |
| UX-08 | **Approve** | A next-step banner whose text follows the data. |
| UX-09 | **Approve** | `#/endpoints` and `#/host(s)` resolve. |
| UX-10, UX-12 | **Approve** | Small copy and icon fixes. |
| UX-11 | **Approve (scoped)** | The visual pass in `04-ui-direction.md`, done in CSS tokens only: no layout rewrite, no new dependency, no external request, every existing behaviour and test unchanged. |
| UX-13, UX-14 | **Approve** | Next-step lines in the server and collector output. |

### Gaps

| ID | Decision |
|---|---|
| GAP-01, 02, 03, 04 | **Approve**: delivered by UX-01/02/03/08/14. |
| GAP-05 | **Approve**: one documented `curl` command, tested against a running server. |
| GAP-06 | **Approve**: collector version shown on the host page. |
| GAP-07 | **Approve**: README "start here". |
| GAP-08 to GAP-13 | **Defer** with reasons in `03-gap-analysis.md`; the release notes state Linux and Administrator runs are unvalidated. |
| GAP-14 | **Blocked on owner.** |
| GAP-15 | **Accept the risk, mitigate by process:** first tag is a pre-release; publication is the last workflow step. |

## Release plan

- Version: **0.1.0 (pre-release)**. The tree says `0.0.0-dev`, nothing has been released, and the first public number
  under the project's SemVer 0.x policy is 0.1.0. `CHANGELOG.md` gets its `[0.1.0]` section from `[Unreleased]`.
- The owner placeholder stays; the release is prepared, not pushed.
- **Go / no-go:** the change is committed only if all of these pass: `go test ./...`, `golangci-lint`, `go vet` on
  Windows and Linux, the browser journey (extended for the new screens), `security.sh`, a run of the collector on this
  machine whose upload shows the new coverage card, and a GoReleaser snapshot build.
- Not done, and said so in the release notes: Linux and Administrator validation, first real run of the release
  workflows, owner identity.
