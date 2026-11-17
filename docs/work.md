# Tracked work, the lifecycle monitor and verified closure

CipherHorizon finds what is wrong with an endpoint, a certificate or a machine. **Work** carries the fix from
there to the end: who owns it, when it is due, who approved it, when the change was made, and whether the change
actually holds. The last step is the point. A piece of work is marked *verified* only when one of the product's
own scans (or a host inventory upload) made **after** the change shows the change in effect. Nobody can mark it
verified by typing, and if a later scan shows the problem back, the product says so.

For a guided tour on the demo targets, and for how to check every claim on this page yourself, read
[lifecycle-walkthrough.md](lifecycle-walkthrough.md).

## Where it lives

- **Work** in the menu (`#/work`): the figures (open, waiting for approval, changed but not verified, verified
  by scan, overdue), where all work stands as one bar, post-quantum key exchange across the endpoints, and three
  tabs: **Work** (the list, with CSV and evidence-pack downloads), **Needs attention** (what the lifecycle
  monitor finds now) and **Suggested** (work the scans point at that nobody has opened).
- **A piece of work** (`#/work/ID`): its stages as a track, the next steps as buttons, the verification with
  the scan it rests on, the details, what it waits for, and its history.
- **Track** buttons where the subject is: *Plan hybrid key exchange* on an endpoint below L3 (or *Track work*),
  *Track* beside a finding on the Findings page, *Plan renewal* on a certificate's page.
- **Settings → Notifications** and **Settings → Integrations** (administrators).

Everything is also in the API (`/api/v1/work`, `/api/v1/workflows`, `/api/v1/lifecycle/*`,
`/api/v1/integrations`; see `/api/v1/openapi.json`), with the same roles, audit trail and token.

## What a piece of work is about

| Subject | What it names | How the product verifies it |
|---|---|---|
| `finding` | One finding on one endpoint or host (`assetId`, `findingKey`, e.g. `PROTO.NO-TLS13`) | The latest complete scan (or host upload) after the change no longer has the finding |
| `certificate` | One certificate by its SHA-256 fingerprint | Every scanned endpoint that served it as its leaf before the change now serves a different certificate that is valid for longer |
| `readiness` | An endpoint and a target readiness level (`targetLevel` 1 to 4) | The latest scan after the change is at or above the target |
| `endpoint` | An endpoint or host, with no measurable target | Not verifiable: closed as *complete* |
| `system` | A system | Not verifiable: closed as *complete* |

A finding must be among the endpoint's current findings when the work is created, and a certificate must be in the
inventory: work cannot be opened on a typo.

Verification answers one of four things, with the scan or upload it read:

- **Verified**: the evidence shows the change in effect;
- **Not verified**: it shows it is not (the finding is still there, the old certificate is still served, the
  level is lower, or the new certificate expires no later than the old one);
- **Waiting for a scan**: no evidence yet. Nothing has been scanned since the change was recorded, or the only
  scan was incomplete. A finding missing from an incomplete scan proves nothing;
- **Cannot be verified by scan**: the product cannot observe this subject that way, for example a system as a
  whole, or a certificate that no scanned endpoint ever served.

*Check now* on a piece of work asks again; it reads and changes nothing. *Scan the endpoint now* queues a scan.

## Workflows

A workflow is a template: stages, and the transitions between them. Each stage may carry one **marker** from a
fixed list, so that lists and figures compare work run under different workflows:

| Marker | Shown as | Means |
|---|---|---|
| `requested` | ○ Requested | the work exists (always the first stage) |
| (none) | ◐ the stage's own name | in progress |
| `approved` | ✓ Approved | a second person approved it |
| `executed` | ◷ Changed, not verified | the change was made: verification looks at evidence after this moment |
| `reported` | ◷ Reported, not verified | whoever made the change reported it working (also a verification baseline) |
| `verified` | ✓ Verified by scan | the product's own evidence shows the change in effect |
| `complete` | ■ Complete | closed as done, verified or not |
| `exception` | ⏸ Risk accepted | the risk is accepted until a date |
| `cancelled` | ✕ Cancelled | closed as not done |

Eight workflows are built in:

| Workflow | For | Verified by |
|---|---|---|
| `certificate-renewal` | Plan, approve, issue, deploy, verify, close | scan |
| `emergency-certificate-replacement` | Replace at once; approval after the fact | scan |
| `tls-configuration-change` | Fix a finding by configuration; or accept the risk until a date (administrator) | scan |
| `pq-key-exchange` | Test client compatibility, approve, enable hybrid ML-KEM groups, reach L3 | scan |
| `pki-signature-migration` | Assess the trust ecosystem, pilot, approve, roll out a post-quantum certificate, reach L4 | scan |
| `library-upgrade` | Choose an upgrade path, approve, upgrade, test the applications | cannot be verified: complete |
| `vendor-dependent` | Ask the vendor, wait with an end date, apply | cannot be verified: complete |
| `manual` | Open, in progress, done | cannot be verified: complete |

### What no workflow can switch off

- A stage marked `verified` is entered only by a transition that requires verification, and only when
  verification says *verified*.
- A stage marked `approved` is entered only by an **approval**, given by a **signed-in person who did not request
  the work** and has not approved it already. With sign-in off, everyone is the same local operator, and the
  automation token is nobody in particular, so approvals are refused. Turn sign-in on, or use a workflow without
  approvals.
- A stage marked `exception` needs a note and an end date in the future.
- A stage that says the change was made or the work is done cannot be entered while a **prerequisite** is
  unfinished. Cycles are refused.
- A viewer cannot change anything. A transition may also require an administrator.
- Two people acting on the same piece of work at once: the second is refused, never applied to a stale stage.

### Your own workflow

An administrator posts a template to `POST /api/v1/workflows`. Start from a copy of a built-in one
(`GET /api/v1/workflows/pq-key-exchange`) under a new id:

```json
{
  "id": "quick-hybrid",
  "title": "Quick hybrid",
  "purpose": "Lab endpoints: enable and verify.",
  "subjects": ["readiness"],
  "stages": [
    {"id": "open", "label": "Open", "marker": "requested"},
    {"id": "enabled", "label": "Enabled", "marker": "executed"},
    {"id": "verified", "label": "Verified", "marker": "verified"},
    {"id": "done", "label": "Done", "marker": "complete", "terminal": true}
  ],
  "transitions": [
    {"id": "enable", "label": "Enable", "from": ["open"], "to": "enabled", "require": ["note"]},
    {"id": "verify", "label": "Verify", "from": ["enabled"], "to": "verified", "verify": true},
    {"id": "close", "label": "Close", "from": ["verified"], "to": "done"}
  ]
}
```

A transition may set `role` (`analyst`, the default, or `admin`), `require` (`note`, `evidence`, `until`),
`approval` and `verify`. The server checks the template before saving it and says what is wrong: every stage
reachable, every stage able to reach a terminal one, an exception that can be reopened, a template that verifies
naming only subjects that can be verified. Posting the same id again saves a new version; work already created
keeps the version it started with. Built-in ids cannot be replaced.

## Suggested work

The **Suggested** tab (`GET /api/v1/work/suggestions`) lists what the scans point at and nobody has opened,
most severe first, each with its reason and, where a standard sets a date, its basis from the policy catalog:

- an endpoint whose latest scan is at L1 (classical key exchange) or L2 (a hybrid group accepted but not what a
  current client gets): *pq-key-exchange* to L3, citing NIST IR 8547's deprecation of quantum-vulnerable key
  establishment after 2030; high when traffic recorded today is exposed;
- a critical or high finding on an endpoint with no triage decision: *tls-configuration-change*;
- a certificate served by a scanned endpoint that expires within the warning window: *certificate-renewal*;
- an RSA, ECDSA or EdDSA certificate valid past 2030: *certificate-renewal* to shorten it, citing IR 8547.

**Track** opens the same dialog as elsewhere, filled in.

## The figures, and what they count

Every figure says what it is out of (`GET /api/v1/work/summary` returns these definitions):

| Figure | Counts |
|---|---|
| Open | work not yet verified, complete or cancelled, out of all work |
| Waiting for approval | open work whose current stage leads to an approval |
| Changed, not verified | work recorded as changed that the product has not yet verified |
| Verified by scan | work whose last verification by the product's own scan said verified, out of all work; *closed without verification* counts complete work the product could not check |
| Overdue | open work past its due date, out of open work with a due date (exceptions excluded) |
| Post-quantum key exchange | scanned endpoints at L3 or above, out of **scanned** endpoints; endpoints never scanned are shown as *unknown*, never as ready or not ready |

## The lifecycle monitor and notifications

Every 15 minutes (`serve --monitor-every`, `0` turns it off), and when an administrator presses *Check now*,
the monitor looks for what needs a person:

| Event | When |
|---|---|
| `work.overdue` | open work past its due date |
| `work.due-soon` | open work due within the due-soon window (3 days by default) |
| `work.awaiting-approval` | open work whose current stage leads to an approval |
| `work.exception-expired` | an accepted risk past its end date |
| `work.regressed` | **verified work that a later scan contradicts**: the finding is back, the old certificate is served again, the level dropped (critical) |
| `certificate.expired` / `certificate.expiring` | a current end-entity certificate expired, or expiring within the warning window (30 days; high within the critical window, 7 days) |
| `certificate.unplanned-change` | an endpoint's two latest complete scans present different certificates and no work names the old one: a change nobody planned, or one nobody recorded |

They are listed on **Work → Needs attention** for anyone. An administrator can send each event **once** to a
webhook (**Settings → Notifications**):

- **JSON** (for scripts and ticketing):
  `{"source":"cipherhorizon","event":"work.overdue","key":"…","severity":"high","title":"…","detail":"…","link":"https://…/#/work/7","firstSeen":"…"}`
- **Chat** (`{"text": "…"}`), which Slack and Microsoft Teams incoming webhooks accept. Teams *Workflows*
  webhooks that require an Adaptive Card are not supported.
- **Signed**: name an environment variable of the server (for example `CH_WEBHOOK_SECRET`) and every message
  carries `X-CipherHorizon-Signature: sha256=<hex HMAC-SHA256 of the body>`. The secret is never stored in the
  database and never returned by the API; the settings only say whether that variable is set.
- **Links** are absolute when the server knows its address (`serve --public-url https://cipherhorizon.example`).
- **Delivery**: one destination, ten seconds per attempt, no redirect followed, five attempts per event, then the
  event is marked failed with the reason. The address obeys the scan guard's rules (no link-local or
  cloud-metadata address; loopback only with `--allow-loopback`), but not the scan scope: a webhook is a
  destination an administrator chose.
- *Send a test message* checks the destination; the recent events and their status are listed under the form.

## Certificates: owner and renewal

A certificate's page has **Ownership and renewal**: who answers for it, how it is renewed (ACME, a CA portal,
cert-manager, managed by a cloud provider, an internal CA, by hand, by a vendor) and notes, recorded with who and
when in the audit log (`PUT /api/v1/certificates/{fingerprint}/lifecycle`). The work that names the certificate is
listed beside it, and *Plan renewal* opens a *certificate-renewal*.

## Integrations

**Settings → Integrations** (`GET /api/v1/integrations`) lists what this server can talk to: what each
connector is for, what it can do, how it authenticates, what it needs and what it cannot do. Two are available
and tested in this version: the **scanner and collectors** (the only source that can verify) and the **webhook**.
Connectors that issue or deploy certificates (ACME and step-ca, cert-manager, Ansible, OpenBao, cloud certificate
services, e-mail) are listed as **planned**, so the roadmap is visible and nobody mistakes it for a feature. The
rules every connector will follow are in ADR-0023.

## Exports for auditors

- **Download CSV** (`/api/v1/work/export.csv`): one row per piece of work, formula-safe.
- **Evidence pack** (`/api/v1/work/evidence.json`): every piece of work with its workflow as it was, its full
  history from the append-only audit log, its prerequisites, and a verification computed at export time, plus the
  definitions of the figures, the evaluation and policy catalog versions.

## The policy catalog

`GET /api/v1/policy/catalog` serves the catalog of standards documents and dated milestones the product acts on
(ADR-0022): each document's status (final or draft), date, address and where it was transcribed from, and each
milestone's effect (deprecated, disallowed, required), date and scope. NIST IR 8547's "deprecated after 2030" and
"disallowed after 2035" come from it, and so do the United States federal dates IR 8547 quotes. A draft (SP
800-131A Rev. 3, FIPS 206) is listed so you can see it exists; nothing the product judges rests on one.

## Limits

- No connector issues or deploys a certificate yet: record what your own tools did, and let the scan verify it.
- One webhook destination; no e-mail.
- A certificate held only on machines (seen by the collector, never served by a scanned endpoint) cannot be
  verified by a scan; close such work without verification, or scan the endpoints that use it first.
- Roles are server-wide: an analyst can act on any work. Per-team scoping is not planned before 1.0.
- `accepted-risk` on a finding (the older triage status) still has no end date; use a workflow's exception stage
  for a time-limited one.
