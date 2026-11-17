# Tracked work, workflows and verified closure

CipherHorizon finds what is wrong with an endpoint, a certificate or a machine. **Tracked work** carries a fix from
there to the end: who owns it, when it is due, who approved it, when the change was made, and whether the change
actually holds. The last step is the point. A piece of work is marked *verified* only when one of the product's
own scans (or a host inventory upload) made **after** the change shows the change in effect. Nobody can mark it
verified by typing.

> **Status.** This is the first milestone (PRD-023, internal): the API, the eight built-in workflows, custom
> workflows and verification. There is no page in the web interface yet, and no connector that makes changes for
> you; both come in later milestones. Everything below works through the API (`/api/v1/work`,
> `/api/v1/workflows`), with the same roles, audit trail and token as the rest of the API.

## What a piece of work is about

| Subject | What it names | How the product verifies it |
|---|---|---|
| `finding` | One finding on one endpoint or host (`assetId`, `findingKey`, e.g. `PROTO.NO-TLS13`) | The latest complete scan (or host upload) after the change no longer has the finding |
| `certificate` | One certificate by its SHA-256 fingerprint | Every scanned endpoint that served it as its leaf before the change now serves a different certificate that is valid for longer |
| `readiness` | An endpoint and a target readiness level (`targetLevel` 1–4) | The latest scan after the change is at or above the target |
| `endpoint` | An endpoint or host, with no measurable target | Not verifiable: closed as *complete* |
| `system` | A system | Not verifiable: closed as *complete* |

A finding must be among the endpoint's current findings when the work is created, and a certificate must be in the
inventory: work cannot be opened on a typo.

Verification answers one of four things, with the scan or upload it read:

- **verified**: the evidence shows the change in effect;
- **not verified**: it shows it is not (the finding is still there, the old certificate is still served, the
  level is lower, or the new certificate expires no later than the old one);
- **waiting**: no evidence yet. Nothing has been scanned since the change was recorded, or the only scan was
  incomplete. A finding missing from an incomplete scan proves nothing;
- **not verifiable**: the product cannot observe this subject that way, for example a certificate that no
  scanned endpoint ever served.

`GET /api/v1/work/{id}/verification` asks at any time; it reads and changes nothing. To check sooner, scan the
endpoint (`POST /api/v1/assets/{id}/scan`).

## Workflows

A workflow is a template: stages, and the transitions between them. Each stage may carry one **marker** from a
fixed list, so that lists and reports can compare work run under different workflows:

| Marker | Means |
|---|---|
| `requested` | the work exists (always the first stage) |
| `approved` | a second person approved it |
| `executed` | the change was made: verification looks at evidence after this moment |
| `reported` | whoever made the change reported it working (also a verification baseline) |
| `verified` | the product's own evidence shows the change in effect |
| `complete` | closed as done, verified or not |
| `exception` | the risk is accepted until a date |
| `cancelled` | closed as not done |

Eight workflows are built in (`GET /api/v1/workflows` lists them with every stage and transition):

| Workflow | For | Verified by |
|---|---|---|
| `certificate-renewal` | Plan, approve, issue, deploy, verify, close | scan |
| `emergency-certificate-replacement` | Replace at once; approval after the fact | scan |
| `tls-configuration-change` | Fix a finding by configuration; or accept the risk until a date (administrator) | scan |
| `pq-key-exchange` | Test client compatibility, approve, enable hybrid ML-KEM groups, reach L3 | scan |
| `pki-signature-migration` | Assess the trust ecosystem, pilot, approve, roll out a post-quantum certificate, reach L4 | scan |
| `library-upgrade` | Choose an upgrade path, approve, upgrade, test the applications | not verifiable: complete |
| `vendor-dependent` | Ask the vendor, wait with an end date, apply | not verifiable: complete |
| `manual` | Open, in progress, done | not verifiable: complete |

### What no workflow can switch off

- A stage marked `verified` is entered only by a transition that requires verification, and only when
  verification says *verified*.
- A stage marked `approved` is entered only by an **approval**, given by a **signed-in person who did not request
  the work** and has not approved it already. With sign-in off, everyone is the same local operator, and the
  automation token is nobody in particular, so approvals are refused. Turn sign-in on, or use a workflow without
  approvals.
- A stage marked `exception` needs a note and an end date in the future.
- A stage that says the change was made or the work is done cannot be entered while a **prerequisite**
  (`PUT /api/v1/work/{id}/dependencies/{otherId}`) is unfinished. Cycles are refused.
- A viewer cannot change anything. A transition may also require an administrator.

### Your own workflow

An administrator posts a template to `POST /api/v1/workflows`. The easiest start is a copy of a built-in one under
a new id:

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

## Using the API

```bash
# Open work on a finding
curl -s -H "Authorization: Bearer $TOKEN" -H "X-Requested-With: cipherhorizon" -H "Content-Type: application/json" \
  -d '{"title":"Enable TLS 1.3 on the gateway","workflow":"tls-configuration-change","owner":"platform","due":"2026-12-31",
       "subject":{"kind":"finding","assetId":12,"findingKey":"PROTO.NO-TLS13"}}' \
  https://cipherhorizon.example/api/v1/work
```

```bash
# Move it along: plan, approve (another signed-in person), record the change, verify, close
curl -s -H "Authorization: Bearer $TOKEN" -H "X-Requested-With: cipherhorizon" -H "Content-Type: application/json" \
  -d '{"transition":"change","note":"ssl_protocols TLSv1.2 TLSv1.3"}' \
  https://cipherhorizon.example/api/v1/work/7/transitions
```

A refused transition answers with a `code` and a sentence: `wrong-stage`, `role` (403), `approval`,
`missing-field`, `until`, `blocked`, `not-verified` (with the verification result) or `moved` (someone else moved
it first). `GET /api/v1/work?marker=open` lists unfinished work; `overdue` and `exceptionExpired` flag work past
its due date and exceptions past their end date.

Every creation, edit, transition and dependency change is in the audit log (object kind `work`) with who, when,
the stage before and after, and the note. Work is cancelled, never deleted.

## The policy catalog

`GET /api/v1/policy/catalog` serves the catalog of standards documents and dated milestones the product acts on
(ADR-0022): each document's status (final or draft), date, address and where it was transcribed from, and each
milestone's effect (deprecated, disallowed, required), date and scope. NIST IR 8547's "deprecated after 2030" and
"disallowed after 2035" come from it, and so do the United States federal dates IR 8547 quotes. A draft (SP
800-131A Rev. 3, FIPS 206) is listed so you can see it exists; nothing the product judges rests on one.

## Limits of this milestone

- No web pages for work yet; no notifications; no connectors that issue or deploy certificates.
- A certificate held only on machines (seen by the collector, never served by a scanned endpoint) cannot be
  verified by a scan; close such work without verification, or scan the endpoints that use it first.
- Roles are server-wide: an analyst can act on any work. Per-team scoping is not planned before 1.0.
- `accepted-risk` on a finding (the older triage status) still has no end date; use a workflow's exception stage
  for a time-limited one.
