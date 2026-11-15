# Scanning everything under a domain

CipherHorizon scans the endpoints it is given. It does not yet find the host names under a domain by itself.
Until it does, a name-finding tool produces the list and **Paste a list** takes it: up to 20,000 lines in one
go.

Scan only domains you own or are authorised to test.

## 1. Get the list of names

The best list is your own DNS zone: export it from your DNS provider or DNS server and keep the host names. It
is the only complete source, and the only one that includes names used inside your network.

Without the zone, an open-source tool can collect names from public sources. Two common ones:

```sh
subfinder -d example.com -silent -o names.txt
```

```sh
amass enum -passive -d example.com -o names.txt
```

Both ask public services (certificate logs, DNS databases) about the domain, so those services learn which
domain you asked about. Neither finds everything: a name that only ever used a wildcard certificate, or only
exists inside your network, will be missing.

## 2. Add the names

1. Open **TLS endpoints** (or **SSH servers**) and choose **Add**, then **Paste a list**.
2. Paste the contents of `names.txt`. A bare name means port 443 for TLS and port 22 for SSH; write
   `name:8443` for another port.
3. Give them a tag such as `example.com`, so the whole domain can be filtered, rescanned and exported together.
4. Leave **Scan now** ticked and submit.

The result says how many lines were added, were already present, or were invalid. Lines that need attention
are listed first; a long list shows the first 200 rows and the counts cover every line. Sending the same list
again is safe: names already present are reported as such and nothing is duplicated.

Names that do not answer are still added. Their scan ends as *unreachable*, which is the honest record that the
name exists and nothing listens on that port. Remove them, or keep them to see when that changes.

## 3. Limit what can be scanned

On a shared server, start it with the domain as the scan scope, so a pasted list cannot reach anything else:

```sh
cipherhorizon serve --scan-allow example.com
```

A name outside the scope is refused when it is added, with the reason.

## From a script

`POST /api/v1/assets/bulk` takes the same list: `{"text": "one name per line", "tags": ["example.com"],
"protocol": "auto"}`. Follow it with `POST /api/v1/scans` and `{"tag": "example.com"}` to scan them. The request
body may be up to 4 MiB. See `/api/v1/openapi.json` on your server for both.

## Keeping it current

Names change. Run the name-finding tool again each month and paste the new list: only names that are new are
added.
