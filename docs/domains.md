# Scanning everything under a domain

Give CipherHorizon a domain and it lists the host names under it, says what answers on each, and lets you choose
which to add and scan. Nothing is added or scanned until you choose.

Look only under domains you own or are authorised to test.

## In the interface

1. Open **TLS endpoints** (or **SSH servers**) and choose **Find from a domain**.
2. Enter the domain alone, such as `example.com`, and tick where to look (below).
3. **Find names** starts the search. It runs in the background, one at a time; you can leave the page and
   come back to it under *Earlier searches*.
4. The result is a list to review. The figures at the top filter it: every name, the names that answer, those
   hosted elsewhere, those on which nothing answered, those that do not resolve and, from the second search of a
   domain on, those that are new.
5. Names that answer and run on your own hosts are ticked for you. Change the choice, then **Add and scan**.

Each name becomes one endpoint per port that answered: port 22 an SSH server, any other port a TLS endpoint.
Every endpoint is tagged with the domain, so the whole domain can be filtered, rescanned and exported together.
Adding the same names again adds nothing twice.

## Where it looks

No single place knows every name. A search combines several and the result says which reported each name.

| Place | What it finds | What leaves this server |
|---|---|---|
| **Already here** | Names in certificates this server has seen, and the endpoints it already has | Nothing |
| **DNS records** | The domain's name servers, mail servers, the hosts its SPF record names, and service records | Ordinary DNS queries |
| **Certificate logs** | Every name that ever got a public certificate, from the Certificate Transparency logs. Usually the most names | **The domain name, to crt.sh.** Off until an administrator turns it on |
| **Common names** | About 1,600 usual labels (`www`, `mail`, `vpn`, `dev-api` ...). A zone that answers for any name is noticed, and guesses that only matched that answer are dropped | A few thousand DNS queries |
| **Your list** | Names you paste, one per line, up to 20,000: an export of your DNS zone, or the output of another tool | Nothing |

Then every name is resolved, and one TCP connection is tried on ports 443, 8443 and 22, and on port 25 for the
hosts the domain's MX records name. Nothing is sent on those connections. Names that share an address share one
check.

### Certificate logs are opt-in

A search of the certificate logs tells an outside service (crt.sh, run by Sectigo) which domain you asked
about. It is off by default, so a server that must not contact the internet keeps working. An administrator
turns it on under **Settings → Finding names from a domain**. crt.sh is free and sometimes slow or
unavailable for large domains; when it does not answer, the search goes on with the other places and says so.

### Your own DNS zone is the complete list

Every outside-in method misses something: a name that only ever used a wildcard certificate, a name used only
inside your network, a name nobody has guessed. Your DNS zone has them all. Export it from your DNS provider or
server, keep the host names, and paste them under **Add names you already know**. Open-source tools such as
`subfinder -d example.com -silent` or `amass enum -passive -d example.com` can add names from further public
sources the same way.

## What the result tells you

- **Hosted elsewhere:** the name is an alias for a host outside the domain, usually a supplier's service. What a
  visitor meets there is still yours to know about, so these can be added, but they are not ticked for you.
- **May not be reached:** the name points at an address the server refuses to connect to (the scan scope, or an
  address such as a cloud metadata service). It is listed with the reason and cannot be added.
- **Do not resolve:** a source named it, and it has no address now. Often a certificate for a host long gone.
- **Already an endpoint / Added:** the name is already in your lists.
- **What this search could not see:** the wildcard certificates it met, sources that were off or failed, and the
  limit of 50,000 names if it was reached.

## The scan scope applies

With `--scan-allow`, a search obeys it. A scope of domains (`--scan-allow example.com`) allows searches under
those domains only. A scope of networks (`--scan-allow 10.0.0.0/8`) allows any domain, and each name found
outside the networks is listed as *may not be reached*.

## From the command line

```sh
cipherhorizon find example.com                      # names that resolve, one per line
cipherhorizon find --ct --wordlist example.com      # also certificate logs and common names
cipherhorizon find --list zone.txt --targets example.com | xargs cipherhorizon tls scan
```

`find` needs no server. `--targets` prints `name:port` for each port that answered; `--json` prints the whole
result; `--ct` sends the domain name to crt.sh. What each source did is printed to standard error.

## From a script or an assistant

`POST /api/v1/discoveries` with `{"domain": "example.com", "sources": ["stored", "dns", "ct", "wordlist"],
"list": "one name per line"}` starts a search; `GET /api/v1/discoveries/{id}` returns its status and names;
`POST /api/v1/discoveries/{id}/accept` with `{"names": [...], "scan": true}` (or `{"all": true}`) adds them. See
`/api/v1/openapi.json` on your server. Starting, accepting, canceling and deleting a search are recorded in the
activity list.

Over the Model Context Protocol, the `domain_find` tool lists names without storing anything
([mcp.md](mcp.md)).

## Keeping it current

Search the domain again each month. The second search marks the names that are new since the first, and the
names you already have are not ticked again.

## Pasting a list without a search

**Add**, then **Paste a list**, still takes up to 20,000 lines directly, without resolving or checking
anything first. Use it when you already know exactly which endpoints you want.
