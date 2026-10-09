# 03 · User experience review: the journeys people will take

2026-10-08. Each journey was walked on the current build (`16dbc82`); the friction points are what a first-time
visitor meets, in order.

## Personas

| Persona | Arrives from | Wants in the first 10 minutes | Comes back for |
|---|---|---|---|
| **The evaluator** (security engineer reading a launch post) | GitHub, HN, Reddit | See it work on a real site; judge credibility | A CLI or CI use, then the app |
| **The PQC programme lead** (security architect, CISO office) | LinkedIn, Offset, a conference | An inventory and a migration order to show leadership | Monthly progress; reports |
| **The platform engineer** | A ticket ("fix TLS on X") | What exactly to change, verified after the change | Re-scan after a fix; certificate expiry |
| **The auditor or manager** | A shared PDF or a viewer account | Evidence, standards cited, no jargon | Quarterly reports |
| **The consultant** (Offset practice, MSSPs) | Engagement kickoff | Fast set-up at a client, a branded report | Each engagement |

## Journey 1: "Does it work?" (the evaluator, from GitHub)

| Step | Today | Friction |
|---|---|---|
| Read the README | A long, internal-sounding document; the demo GIF shows an old UI | **High.** The value is not in the first screen; there is no screenshot of a report |
| Install | `docker compose up` (builds locally; no published image) or download a binary (no release yet) | **High.** No `docker run ghcr.io/…` one-liner; nothing published |
| First start | Must find the setup code in the log | Medium. Fine for operators; surprising for a 2-minute trial |
| Create the administrator | Clear | Low |
| Scan a site | The Overview hero works; the report is strong | Low |
| Judge credibility | Every check listed, sources cited, PQC level explained | Strength |
| Try it in CI | `tls scan` prints a raw probe: **no readiness level, no findings, no exit code by threshold** | **High.** No CI story at all |
| Scan a mail server | **No STARTTLS** (SMTP, IMAP, POP3, LDAP, XMPP, FTP, Postgres) | **High** for anyone comparing with testssl.sh |

## Journey 2: "Give me an inventory and an order" (the programme lead)

| Step | Today | Friction |
|---|---|---|
| Add many endpoints | Paste a list (up to 1,000) | Medium. **No discovery**: no CIDR range or domain expansion, no import from a CMDB/CSV of hosts |
| Inventory machines | Scripts with a clear guide; real Windows run validated | Medium. The Linux script is not yet validated on real distributions |
| See the order | Systems ranks by exposure and data lifetime; owner details editable | Medium. Systems need owner details before the order is meaningful; there is no bulk edit |
| Show leadership | Inventory PDF and endpoint PDFs | Medium. **No trend over time** for the fleet (progress is the story leadership wants) |
| Keep it current | Scheduled rescans per endpoint | **High.** **No notifications** (certificate expiring, a scan got worse); nobody looks every day |

## Journey 3: "What do I change?" (the platform engineer)

| Step | Today | Friction |
|---|---|---|
| Open the report | Action items grouped, "what to do" per item | Strength |
| Get the config | Advice is in words, not in the server's language | Medium. No ready snippets for nginx, Apache, IIS, HAProxy, Caddy or OpenSSL (*the Mozilla SSL config generator is the reference*) |
| Verify the fix | Scan again; the diff against the last scan | Strength |

## Journey 4: "Show me the evidence" (auditor or manager)

| Step | Today | Friction |
|---|---|---|
| Receive a PDF | A clean report with sources | Strength |
| Sign in as a viewer | Read and download only | Strength |
| Standards mapping | NIST, IANA, RFCs cited per finding; M-23-02 export | Medium. No view per standard ("CNSA 2.0 readiness", "NIST IR 8547 2030 list") |

## Journey 5: "Run it at a client" (the consultant)

| Step | Today | Friction |
|---|---|---|
| Set up at the client | One binary or container | Low |
| Brand the report | Offset credit on the PDF | Medium. **No report branding** (client name, assessor, logo); PDF says CipherHorizon only |
| Hand over | PDF + CBOM | Strength |

## Cross-cutting

1. **The product does not tell its own story inside itself.** The sign-in screen, About page and empty states
   are functional, not persuasive. A visitor who signs in to a demo does not learn the two USPs (PQC readiness level
   and the TLS scanner depth) from the product itself.
2. **The visual identity is not Offset's.** The current UI uses its own indigo and Inter; the logo has a gradient
   and a glow. The developer credit is the only Offset element.
3. **Empty states teach, but there is no sample data.** An evaluator without their own targets sees nothing; a
   "load sample results" or the public demo fixes that.
4. **No docs site.** Everything is in Markdown in the repository; there is no getting-started page to link from a
   launch post.

## Summary of gaps (ranked by launch impact)

| Rank | Gap | Who it blocks |
|---|---|---|
| 1 | Nothing published: no release, no image, no demo, outdated README and GIF | Everyone |
| 2 | CLI gives no verdict and no CI exit code | Evaluator, platform engineer |
| 3 | No STARTTLS | Evaluator, platform engineer |
| 4 | Product does not advertise its USPs; brand is not Offset's | Evaluator, buyer |
| 5 | No notifications (expiry, regression) | Programme lead, platform engineer |
| 6 | No discovery (CIDR or domain expansion, CSV import of hosts) | Programme lead |
| 7 | No fleet trend over time | Programme lead, manager |
| 8 | No config snippets per server | Platform engineer |
| 9 | No report branding | Consultant |
| 10 | No standards views (CNSA 2.0, IR 8547 lists) | Auditor |
