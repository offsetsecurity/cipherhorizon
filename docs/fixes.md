# Fixes and Renewals

CipherHorizon finds what is wrong with an endpoint or a certificate. **Fixes** and **Renewals** take it from
there: you say who will fix a problem and by when, and every scan after that checks it for you. A fix is marked
fixed only when a scan shows the problem gone, and it comes back to the top of the list if a later scan finds the
problem again. Nobody can mark a fix as done by hand.

For a fifteen-minute tour on the demo targets, and how each claim here is tested, read
[lifecycle-walkthrough.md](lifecycle-walkthrough.md).

## Fixes

**Fixes** in the menu lists, top to bottom:

| Section | What is in it |
|---|---|
| The progress line | How many scanned endpoints keep today's traffic safe from later decryption (post-quantum key exchange in use), how many are being fixed, how many are not started. Endpoints never scanned are counted apart, never as safe or unsafe |
| **Came back** | Fixes a scan had confirmed, where a later scan found the problem again |
| **Being fixed** | Assigned fixes, each with one sentence: *Not checked yet*, *Not fixed yet. Checked 2 hours ago*, or *Overdue* |
| **To fix next** | What the scans found that nobody has been given, most serious first, one line per endpoint |
| **On hold** | Fixes put aside until a date |
| **Fixed and still holding** | Fixes a scan confirmed and every scan since has agreed with |

### Assign

Press **Assign** on a line of *To fix next* (or **Assign the fix** on an endpoint's page, **Assign** beside a
finding, **Assign the renewal** on a certificate). The form asks three things:

- **Who will fix it**: a person or a team.
- **By when**.
- **Your ticket** (optional): a link to the change in Jira, ServiceNow or wherever you track changes. Approvals
  and change windows stay there; CipherHorizon only links to it.

That is all you do. An endpoint with a fix assigned is scanned every day from then on if it had no schedule.

### What the scans do

| A scan after the assignment shows | The fix reads |
|---|---|
| the problem still there | **Not fixed yet**, with when it was checked |
| the problem gone (a complete scan) | **Fixed**, confirmed by the scan of that day |
| the problem again, after it was fixed | **Came back**: was fixed, the scan of that day found it again |

What counts as gone:

| The fix is about | Fixed when |
|---|---|
| post-quantum key exchange on an endpoint | a current client negotiates a hybrid post-quantum group with it |
| a finding on an endpoint | a complete scan no longer has the finding. A finding missing from an incomplete scan proves nothing |
| a certificate | every scanned endpoint that served it now serves a certificate issued after it and valid now, whatever its lifetime |

A scan cannot check everything. A finding on a machine comes from an uploaded inventory file, which is a document
someone sends, not something this product observed; such a fix reads *A scan cannot check this one* and you close
it yourself with a note. It is then counted as closed, not as fixed.

### One fix

A fix's page says where it stands in one line, what the last scan saw, **how to fix it** (the remedy from the
finding, with its sources and a link to the full report), and **what has happened**: assigned, confirmed by a
scan, came back. **Scan now** checks at once; **Change owner or date** edits the assignment.

**Put on hold** takes a reason and a date within a year. A fix on hold is not overdue, and comes back by itself on
the date. **Drop it** closes a fix that is not needed, with the reason.

## Renewals

**Renewals** lists every certificate a scanned endpoint serves, by the date it runs out, with four months of bars
above. Each line says how long is left, how many endpoints serve it, who issued it or how it is renewed, and who
has the renewal. **Assign** works as on Fixes; the renewal is done when a scan sees a newer certificate on every
endpoint that served the old one.

**Changed without anyone assigned** lists endpoints whose latest scan found a different certificate while nobody
had a renewal assigned: a change nobody planned, or one nobody recorded. **It was expected** removes it from the
list (and is recorded with who said so).

On a certificate's page, **Owner and renewal** records who answers for it and how it is renewed (ACME, a CA
portal, cert-manager, a cloud provider, an internal CA, by hand, a vendor).

## Being told

Open the pages, or have the server tell you. An administrator sets a webhook in **Settings → Notifications**; the
server then sends each of these once:

| Event | When |
|---|---|
| `work.regressed` | a fix came back |
| `work.overdue`, `work.due-soon` | a fix is past its date, or within 3 days of it |
| `certificate.expiring`, `certificate.expired` | a served certificate runs out within 30 days (high within 7), or has |
| `certificate.unplanned-change` | a certificate changed with nobody assigned |

- **JSON** for scripts and ticketing, or **chat** (`{"text": "…"}`, the shape Slack and Microsoft Teams incoming
  webhooks document; not tested against either service).
- **Signed**: name an environment variable of the server that holds a secret, and every message carries
  `X-CipherHorizon-Signature: sha256=<HMAC-SHA256 of the body>`. The secret is never stored or shown. If the named
  variable is not set, nothing is sent and the settings say so.
- The webhook address itself is stored in the server's database; treat it as a secret where it is one. A failed
  delivery records the host, never the full address.
- One destination; ten seconds per attempt; no redirect followed; five attempts, then the event is marked failed.
  The address obeys the scanner's rules: no link-local or cloud-metadata address.
- `serve --monitor-every` sets how often the server looks (15 minutes); `--public-url` makes the links absolute.

## For auditors

**Download the record for an auditor** on Fixes gives every fix with its full history from the append-only audit
log (who assigned it, which scan confirmed it, when it came back) and a check computed again at the moment of
export.

## The API

`GET /api/v1/fixes`, `POST /api/v1/fixes` (assign), `GET /api/v1/fixes/{id}`, `GET /api/v1/renewals`,
`POST /api/v1/renewals/expected`; put on hold, resume, close and drop are `POST /api/v1/work/{id}/transitions`
with `hold`, `resume`, `close`, `drop`. All are in `/api/v1/openapi.json`, with the same roles and token as the
rest of the API (a viewer reads; an analyst assigns).

Underneath, a fix is a piece of work on a built-in workflow, and the API also offers workflows of your own with
stages, approvals and prerequisites (`/api/v1/work`, `/api/v1/workflows`; ADR-0021). They are not in the web
interface: teams keep their process in their own ticket tool.

## Integrations

**Settings → Integrations** lists what this server can talk to. Two are available: the scanner (the only thing
that decides a fix is fixed) and the webhook. Connectors that issue or deploy certificates, or create the ticket in
Jira or ServiceNow for you, are listed as **planned**; ADR-0023 sets the rules they will follow.

## Limits

- CipherHorizon does not make the change, issue a certificate or hold a key. It checks what your tools did.
- It sees what a client sees. A library upgraded inside an application is not visible from outside.
- A certificate only machines hold (never served by a scanned endpoint) is not on Renewals.
- One webhook destination; no e-mail.
- Roles apply to the whole server: an analyst can assign any fix.
