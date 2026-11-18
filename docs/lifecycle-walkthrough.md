# Walkthrough: from a problem to a fix the scans confirmed

The job CipherHorizon's Fixes and Renewals pages are for, played on the demo targets in about fifteen minutes on
one machine, followed by how each claim it makes is tested. The reference is [fixes.md](fixes.md).

## The story

A platform team scans its endpoints. One negotiates a classical key exchange: traffic recorded today could be
decrypted once a quantum computer exists. The team lead presses **Assign**, names the platform team and a date,
pastes the link to the change ticket, and does nothing else. That night's scan says *Not fixed yet*. The engineer
makes the change; the next scan says *Fixed*, with the date, and nobody pressed anything. Weeks later someone
reverts the configuration; the next scan moves the fix to *Came back* at the top of the page and the team is told.
The auditor downloads the record: who was assigned, which scan confirmed the fix, when it came back.

## Set up

```bash
go build -o dist/cipherhorizon ./cmd/cipherhorizon && go build -o dist/demo-targets ./cmd/demo-targets
```

```bash
./dist/demo-targets
```

```bash
./dist/cipherhorizon serve --allow-loopback --db walkthrough.db
```

Open `http://127.0.0.1:8080`. No sign-in is needed for this tour.

## 1. See what needs fixing

**TLS endpoints → Add TLS endpoints**, paste these and let them scan:

```
127.0.0.1:9440
127.0.0.1:9441
127.0.0.1:9443
127.0.0.1:9445
```

Open **Fixes**. The progress line says how many of the four scanned endpoints keep today's traffic safe from
later decryption (one: `9440`). **To fix next** lists the rest, most serious first, one line per endpoint: `9443`
accepts connections with no authentication (critical, with "6 more serious problems on this server"); `9441` and
`9445` need post-quantum key exchange, with a link to the NIST date behind it.

## 2. Assign

Press **Assign** on the `127.0.0.1:9445` line. Fill in who and by when; paste any link as the ticket. Press
**Assign**. The fix opens: *Not checked yet*, how to fix it, and one line of history. The endpoint is now scanned
every day.

There is nothing else to do on this page, and no button that says the problem is fixed.

## 3. The scans decide

Press **Scan now**. The endpoint has not changed, so the page turns to *Not fixed yet. Checked just now.*

Make the change for real (the demo target has a switch for it):

```bash
curl -X POST http://127.0.0.1:9447/pq/on
```

Press **Scan now** again. The page turns to *Fixed. Confirmed by the scan of* today, and the history gains
*A scan confirmed it is fixed.* On **Fixes** it has moved under *Fixed and still holding*, and the progress line
counts one more endpoint.

## 4. It comes back

Undo the change, as someone eventually will:

```bash
curl -X POST http://127.0.0.1:9447/pq/off
```

Scan `127.0.0.1:9445` again (or wait for its daily scan). **Fixes** now opens with *Came back*: *Was fixed. The
scan of* today *found it again.*

## 5. Renewals

Open **Renewals**: the certificates those endpoints serve, by the date they run out. Press **Assign** on one, name
the PKI team. When a scan later sees a newer certificate on every endpoint that served it, the renewal is done; if
a certificate changes with nobody assigned, it appears under *Changed without anyone assigned*.

## 6. Being told

In **Settings → Notifications**, set a webhook address and press **Save**, then **Send a test message**. A
receiver to watch them locally:

```bash
python3 -c "import http.server as s
class H(s.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers['Content-Length']); print(self.headers.get('X-CipherHorizon-Event'), self.rfile.read(n).decode()); self.send_response(204); self.end_headers()
s.HTTPServer(('127.0.0.1', 9099), H).serve_forever()"
```

With the webhook `http://127.0.0.1:9099/` saved, repeat step 4 and press **Run the monitor now**: the *came back*
event arrives once, and is not sent again on the next pass. (An event the server first saw before a webhook was
set is listed but not sent.)

## 7. The record

**Fixes → Download the record for an auditor**: every fix with who assigned it, which scan confirmed it, when it
came back, and a check computed again at export.

## How this is tested

Each claim above has a test in the repository's CI. Results of a given run are in that run, not on this page.

| Claim | Test |
|---|---|
| Assigning is one form; a second assignment of the same problem is refused; the endpoint gets a daily scan | `TestAFixIsDecidedByScansAlone`; browser E2E-FX.1, E2E-FX.2 |
| Only scans change a fix: unchanged reads not fixed, changed reads fixed, undone comes back | `TestAFixIsDecidedByScansAlone` (real scans of a test server restarted with and without TLS 1.3); browser E2E-FX.3, E2E-FX.4, E2E-FX.6 on the demo toggle |
| No page offers a way to mark a fix fixed, and none uses process vocabulary | browser E2E-FX.2, E2E-FX.2b, E2E-FX.5 |
| A finding missing from an incomplete scan is not a fix; an uploaded machine inventory never confirms one | `internal/server/work.go` rules, exercised by `TestAFindingIsVerifiedOnlyByAScanAfterTheChange` (incomplete-scan and upload branches have no dedicated test yet) |
| A renewal is done when every endpoint serves a certificate issued after the old one; an older certificate put back is not a renewal | `TestACertificateReplacementIsVerifiedOnEveryEndpoint`, `TestRenewals` |
| A certificate changed with nobody assigned is listed until someone says it was expected | `TestRenewals` |
| On hold needs a reason and a date within a year, and resumes by itself | `TestAFixIsDecidedByScansAlone`, `TestDependenciesExceptionsAndDueDates`; browser E2E-FX.7 |
| Progress counts out of scanned endpoints | `TestFixesProgressCountsOutOfScannedEndpoints`; browser E2E-FX.5 |
| Each event is sent once, signed; the secret never appears; a metadata address is refused | `TestTheMonitorSendsEachEventOnceSigned`, `TestTheWebhookObeysTheAddressGuard` |
| The pages fit a phone | browser E2E-FX.11 |

```bash
go test ./internal/workflow ./internal/policy ./internal/store ./internal/server
```

The browser journey (`testing/e2e/journey.mjs`) needs the demo targets and a server started as the `e2e` job in
`.github/workflows/ci.yml` does.

## What it does not do

- It does not make the change, issue or deploy a certificate, or hold a private key.
- It does not create the ticket in your tracker yet; you paste the link.
- It cannot see inside an application: a library upgrade is not something a scan confirms.
