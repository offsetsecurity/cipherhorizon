# Walkthrough: from a finding to a change the product has verified

This is the story CipherHorizon's lifecycle features are built for, played on the demo targets so you can run it
in fifteen minutes on one machine, followed by how each claim it makes was tested and how to test it yourself.
The reference for every screen and setting is [work.md](work.md).

## The story in one paragraph

A platform team scans its endpoints. One negotiates classical key exchange: traffic recorded today could be
decrypted once a quantum computer exists. The team lead opens work on it from the endpoint's page, *Bring it to
hybrid key exchange*, with an owner, a due date and a project. An engineer records the client compatibility test.
A second person approves; the lead could not have. The change is recorded as made, and the product **refuses to
call it verified**: no scan has run since. A scan runs and still finds classical key exchange: someone changed the
wrong server. The engineer fixes it for real; the next scan shows hybrid key exchange negotiated, and only now
does the work move to *Verified by scan* and close. Weeks later someone reverts the configuration; the next
scheduled scan sees it and the monitor reports, as critical, that verified work no longer holds. The auditor gets
the evidence pack: every step, who took it, and a verification computed again at export.

## Set up (five minutes)

```bash
go build -o dist/cipherhorizon ./cmd/cipherhorizon && go build -o dist/demo-targets ./cmd/demo-targets
```

```bash
./dist/demo-targets
```

```bash
./dist/cipherhorizon serve --allow-loopback --sign-in on --db walkthrough.db
```

The server prints a one-time setup code. Open `http://127.0.0.1:8080`, enter the code, and create the
administrator (the *team lead* below). In **Users**, add a second account with the role *analyst* (the
*approver*). Approvals need two people who can be told apart, which is why sign-in is on.

## 1. Discover and assess

**TLS endpoints → Add TLS endpoints**, paste:

```
127.0.0.1:9440
127.0.0.1:9441
127.0.0.1:9442
127.0.0.1:9445
```

and let them scan. `9440` negotiates hybrid key exchange (L3); `9441` and `9445` only classical (L1); `9442`
offers no TLS 1.3 (L0). `9445` is the one you will change: the demo targets let you switch its post-quantum key
exchange on and off.

Open **Work → Suggested**. The scans already point at work nobody has opened: hybrid key exchange for the L1
endpoints (citing NIST IR 8547's deprecation of quantum-vulnerable key establishment after 2030), the high
findings, certificates near their end. The **Post-quantum key exchange** bar above the tabs counts the endpoints
at L3 out of those **scanned**, and keeps the never-scanned apart as unknown.

## 2. Plan

Open `127.0.0.1:9445` and press **Plan hybrid key exchange**. The dialog proposes the *Post-quantum key exchange*
workflow and says how the work will close: *verified only when a later scan shows a current client negotiating a
hybrid group*. Set an owner, a due date and the project `PQC wave 1`, and create it.

The work's page shows its stages as a track: *Requested → Client compatibility tested → Approved → Hybrid groups
enabled → Verified by scan → Closed*. **Record the compatibility test** needs evidence: a change ticket, a log
line, a link. Without it the step is refused, in words.

## 3. Approve

Press **Approve** as the team lead: refused, *the person who requested this work cannot approve it*. Sign out,
sign in as the approver, open the work and approve. The details now say who approved it. (With sign-in off, or
with the automation token, approvals are refused: nobody can be told apart.)

## 4. Execute

Your own tools make the change; CipherHorizon records it. Press **Record that it is enabled** and say what was
changed. The stage is now *Changed, not verified*, and the change's time is the baseline every verification
looks after.

(Connectors that make the change themselves, such as ACME issuance or an Ansible playbook, are planned and listed
in **Settings → Integrations**. They will act only on approved work and will never mark their own change
verified.)

## 5. Verify

Press **Verify**: refused, *no scan of 127.0.0.1:9445 has finished since the change was recorded*. The product
does not take anyone's word for it.

Press **Scan the endpoint now**, wait for the scan, press **Check now**: *Not verified, scan N is at L1
(Exposed); the target is L3*. The change was never applied to this server.

Now apply it for real:

```bash
curl -X POST http://127.0.0.1:9447/pq/on
```

Scan again, **Check now**: *Verified, scan N reached L3 (Hybrid negotiated)*. Press **Verify**, then **Close**.
The history reads as the story: created, tested (with the evidence), approved by the approver, enabled (with the
note), verified (with the scan it rests on), closed.

## 6. Monitor

Revert the change, as someone eventually will:

```bash
curl -X POST http://127.0.0.1:9447/pq/off
```

Scan `9445` again (or let `Rescan automatically` do it) and open **Work → Needs attention**: *No longer holds:
Bring 127.0.0.1:9445 to hybrid key exchange*, critical, with the scan that shows it.

To have such events pushed, go to **Settings → Notifications** as the administrator, set a webhook address, and
optionally the name of an environment variable holding a signing secret. A minimal receiver to watch them
locally:

```bash
python3 -c "import http.server as s
class H(s.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers['Content-Length']); print(self.headers.get('X-CipherHorizon-Event'), self.rfile.read(n).decode()); self.send_response(204); self.end_headers()
s.HTTPServer(('127.0.0.1', 9099), H).serve_forever()"
```

Set the webhook to `http://127.0.0.1:9099/`, press **Send a test message**, then **Check now**: each event
arrives once, and is not sent again on the next pass.

The same monitor reports certificates expiring within the warning window, and a certificate that **changed with
no work naming the old one**: a change nobody planned, or one nobody recorded.

## 7. Report

**Work → Download CSV** gives one row per piece of work. **Evidence pack (JSON)** gives each piece of work with
its workflow as it was when the work started, its full history from the append-only audit log, and a verification
computed again at export time, with the definitions of every figure and the versions of the rules applied. An
auditor can check, from that file alone, that every *verified* rests on a scan made after the change.

## How this was validated

Every claim above is a test that runs in CI. The table names them; run them yourself with the commands below.

| Claim | Evidence |
|---|---|
| A stage marked verified cannot be entered without the product's verification, whatever the workflow says | `TestValidateRefusesTemplatesThatBendTheRules`, `TestACustomTemplateCannotSkipVerification`, `TestCustomWorkflowsAndAReadinessTarget` (a custom template with a shortcut is refused with 400) |
| A finding is verified only by a complete scan after the change; a rescan that still finds it says so | `TestAFindingIsVerifiedOnlyByAScanAfterTheChange` (real scans of a test server restarted with TLS 1.3) |
| A certificate replacement is verified only when every endpoint that served it serves a different one valid for longer | `TestACertificateReplacementIsVerifiedOnEveryEndpoint` (two endpoints, a shorter replacement refused) |
| A readiness target is verified by the level a later scan reaches | `TestCustomWorkflowsAndAReadinessTarget`; browser: E2E-WK.6 to E2E-WK.8 |
| The requester cannot approve; nor can the automation token or anyone with sign-in off | `TestCheckEnforcesEveryGuard`, `TestAFindingIsVerifiedOnlyByAScanAfterTheChange`, `TestACertificateReplacementIsVerifiedOnEveryEndpoint`; browser: E2E-WK.4, E2E-WK.5 |
| Prerequisites block, cycles are refused, exceptions need an end date in the future | `TestWorkDependenciesRefuseCycles`, `TestDependenciesExceptionsAndDueDates` |
| Every step is in the append-only audit log with who and why | `TestWorkIsStoredAuditedAndMovedOnlyFromItsCurrentStage`, `TestWorkEditsAreAuditedAndCleaned`, `TestEveryChangeIsAudited`; browser: E2E-WK.9 |
| Verified work that a later scan contradicts is reported; so is a certificate changed without planned work | `TestRegressionsAndUnplannedCertificateChanges`; browser: E2E-WK.13 |
| Each event is sent once, signed, retried five times then marked failed; the secret never appears in the API | `TestTheMonitorSendsEachEventOnceSigned` |
| A webhook cannot be pointed at a cloud-metadata address | `TestTheWebhookObeysTheAddressGuard` |
| Suggestions come from the scans, cite their basis and disappear once work is opened; readiness counts the unscanned as unknown | `TestSuggestionsAndTheSummaryAreHonest`; browser: E2E-WK.10, E2E-WK.11 |
| The IR 8547 dates come from a catalog that refuses a deadline resting on a draft | `TestValidateRefusesEachBrokenRule`, `TestTheIR8547MilestonesMatchTheDocument`, `TestCertificateRules` |
| The screens work end to end, in a real browser, at 1440 px and at 390 px | `testing/e2e/work-phase.mjs`, E2E-WK.1 to E2E-WK.16 |

```bash
go test ./internal/workflow ./internal/policy ./internal/store ./internal/server
```

```bash
E2E_TOKEN=e2e-automation-token-0123456789 E2E_SERVER_LOG=serve.log node testing/e2e/journey.mjs --base http://127.0.0.1:8090
```

(the second needs the demo targets and a server started as in `.github/workflows/ci.yml`, job `e2e`).

## What it does not do

- It does not issue, deploy or revoke certificates, and it never holds a private key. It verifies what your tools
  did.
- It cannot see inside an application: a library upgrade closes as *complete*, never *verified*.
- One webhook destination; no e-mail yet.
- Roles apply to the whole server; there are no per-team scopes.
