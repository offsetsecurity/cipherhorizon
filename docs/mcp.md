# Using CipherHorizon from an assistant (MCP)

CipherHorizon speaks the [Model Context Protocol](https://modelcontextprotocol.io), so an assistant that
can call tools (Claude Desktop, Claude Code, Cursor, VS Code, and others) can scan an endpoint, read the
verdict in the product's own words, quote the standard clause behind a finding, and, with a running
server, look over the whole fleet.

Two ways to run it:

| | `cipherhorizon mcp` | `cipherhorizon serve --mcp` |
|---|---|---|
| Where | On the machine that runs the assistant (or any machine, over HTTP) | On the server that already serves the web interface |
| Transport | stdio by default; `--listen` for Streamable HTTP | Streamable HTTP at `/mcp` |
| Ad-hoc scans | `tls_scan`, `ssh_scan` (the same probe and judgement as `tls scan` and `ssh scan`) | Only with `--mcp-scan` |
| The fleet | With `--server URL --token TOKEN` | Always; each call runs under the caller's own role |
| Credentials | The server's automation token, or `--key` for the HTTP listener | The server's sign-in or token, unchanged |

Both offer the reference catalogues as resources: every standard clause by clause, the SSH baselines,
the simulated clients, and the readiness scale.

## The tools

Names are fixed; the assistant sees a description of each, written for it.

| Tool | What it does | Changes anything? |
|---|---|---|
| `tls_scan` | Scan one TLS endpoint now: readiness level, hygiene score, findings with remediation, standards clause by clause, which clients connect. Nothing is stored. | No (connects to the target) |
| `ssh_scan` | Scan one SSH server now: readiness, baseline conformance with the `sshd_config` lines that would meet it, findings, standards. Never logs in. | No (connects to the target) |
| `fleet_summary` | The Overview in numbers: endpoints by level and band, findings by severity, the trend. | No |
| `endpoints_list` | Tracked endpoints with their latest verdict; filter by protocol, tag, text or state (`not-ready`, `failing`, `hndl-exposed`, `never-scanned`); paged. | No |
| `endpoint_get` | One endpoint's latest completed scan, judged, plus its history. | No |
| `endpoint_add` | Track a new endpoint, optionally queue its first scan. | Yes |
| `scan_start` | Queue stored scans by ids, tag, or all. | Yes |
| `scan_get` | A stored scan's status and, once done, its verdict. | No |
| `findings_list` | Every open finding across the fleet, worst first; filter by severity, status, protocol. | No |
| `standards_summary` | Per standard: how many endpoints meet it, do not, or could not be assessed. | No |
| `machines_list`, `machine_get` | The host inventory: machines and what each carries. | No |
| `inventory_summary` | The inventory's front page in numbers. | No |
| `cbom_get` | A CycloneDX CBOM: one stored scan's, or the merged inventory. | No |

Every scan tool returns two things: the verdict text the CLI would print (the assistant reads it as you
would) and a structured summary with a schema (readiness, hygiene or baseline, standards verdicts, what to
fix first, findings). The `detail` argument chooses `verdict` (default), `findings` or `full`.

Prompts: `assess_endpoint` (scan and explain) and `fleet_review`.

## The assistant is an untrusted caller

Treat the assistant as you would a script someone else wrote: it can be talked into calling tools by the
content it reads. CipherHorizon limits what the tools can do, and you choose how far:

- **Scan scope.** Ad-hoc scans pass the same guard as the server's: link-local, metadata and (unless
  `--allow-loopback`) loopback addresses are refused. `--scan-allow 10.0.0.0/8` (repeatable; a network,
  an address, or a domain and the names under it) limits scans to what you name. Without a scope, anything
  routable is scannable, as it is for `tls scan`.
- **`--no-scan`** removes `tls_scan` and `ssh_scan`: the assistant reads stored results only.
- **`--read-only`** removes `endpoint_add` and `scan_start`: nothing the assistant does changes the server.
- **Roles.** Through `serve --mcp`, each tool call is an API call made as the signed-in user or token:
  a viewer gets read-only automatically; the audit trail records the calls.
- **Keys.** The HTTP listener of `cipherhorizon mcp` needs `--key` (16+ characters; or
  `CIPHERHORIZON_MCP_KEY`) unless it is on loopback, and refuses requests from a browser page (foreign
  `Origin`, cross-site). It binds to the address you give it; keep it on `127.0.0.1` unless you mean
  otherwise.
- **Size.** Results are bounded: lists are paged (`limit`, `offset`), the full evaluation is returned only
  while it fits in 200 KiB, and a larger CBOM is pointed at rather than returned.

A scan makes a few hundred short TLS handshakes or at most 24 SSH connections to the target and sends
nothing beyond them except, for TLS, one `HTTP GET /` read for headers (`httpChecks: false` turns it off).
Scan only systems you are authorised to test.

## Setting it up

### Claude Code

Local scans only:

```bash
claude mcp add cipherhorizon -- cipherhorizon mcp
```

With your team's server (the token is the one `serve --token` or `CIPHERHORIZON_TOKEN` was started with):

```bash
claude mcp add cipherhorizon --env CIPHERHORIZON_TOKEN=YOUR-TOKEN -- cipherhorizon mcp --server https://cipherhorizon.example.net --read-only
```

Or connect straight to the server's own endpoint:

```bash
claude mcp add --transport http cipherhorizon https://cipherhorizon.example.net/mcp --header "Authorization: Bearer YOUR-TOKEN"
```

A project can share the configuration in `.mcp.json`:

```json
{
  "mcpServers": {
    "cipherhorizon": {
      "command": "cipherhorizon",
      "args": ["mcp", "--server", "https://cipherhorizon.example.net", "--read-only", "--scan-allow", "10.0.0.0/8"],
      "env": { "CIPHERHORIZON_TOKEN": "${CIPHERHORIZON_TOKEN}" }
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows: `%APPDATA%\Claude\`).
Use the binary's full path; on Windows double the backslashes.

```json
{
  "mcpServers": {
    "cipherhorizon": {
      "command": "C:\\Program Files\\CipherHorizon\\cipherhorizon.exe",
      "args": ["mcp", "--server", "https://cipherhorizon.example.net"],
      "env": { "CIPHERHORIZON_TOKEN": "YOUR-TOKEN" }
    }
  }
}
```

Claude Desktop reaches an HTTP server through Settings → Connectors → Add custom connector, with the URL
`https://cipherhorizon.example.net/mcp`; it needs HTTPS and the token as a bearer header, which that
dialog may not offer. The stdio form above works in every case.

### Cursor

`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "cipherhorizon": {
      "command": "cipherhorizon",
      "args": ["mcp", "--server", "https://cipherhorizon.example.net"],
      "env": { "CIPHERHORIZON_TOKEN": "${env:CIPHERHORIZON_TOKEN}" }
    }
  }
}
```

For the HTTP endpoint: `{ "url": "https://cipherhorizon.example.net/mcp", "headers": { "Authorization": "Bearer ${env:CIPHERHORIZON_TOKEN}" } }`.

### VS Code

`.vscode/mcp.json` uses the key `servers`, not `mcpServers`:

```json
{
  "servers": {
    "cipherhorizon": {
      "type": "stdio",
      "command": "cipherhorizon",
      "args": ["mcp", "--server", "https://cipherhorizon.example.net"],
      "env": { "CIPHERHORIZON_TOKEN": "${env:CIPHERHORIZON_TOKEN}" }
    }
  }
}
```

### An HTTP listener of its own

For a client that speaks only HTTP, or to keep one scanner process for several assistants:

```bash
cipherhorizon mcp --listen 127.0.0.1:8075 --key "$(openssl rand -hex 24)" --scan-allow 10.0.0.0/8
```

The endpoint is `http://127.0.0.1:8075/mcp`; clients send `Authorization: Bearer <key>`. `GET /healthz`
answers `ok` for a supervisor. Put a TLS-terminating proxy in front before exposing it beyond the machine.

### The server's own endpoint

```bash
cipherhorizon serve --mcp            # fleet tools at /mcp, same sign-in or token as the API
cipherhorizon serve --mcp --mcp-scan # also tls_scan and ssh_scan, for every signed-in caller
```

The container image, the systemd unit and the Windows service take the same flags
([deploy.md](deploy.md)). `--mcp-scan` lets any signed-in user, whatever the role, scan from the
server's network position within its scan scope; leave it off unless that is wanted.

## Checking it works

```bash
cipherhorizon mcp --verbose    # then type nothing; Ctrl-C. It must print its banner to stderr and nothing to stdout.
```

The MCP Inspector exercises any server: `npx @modelcontextprotocol/inspector --cli cipherhorizon mcp --method tools/list`
lists the tools, and `--method tools/call --tool-name tls_scan --tool-arg target=example.com` runs one.

In Claude Code, `/mcp` shows the server and its tools; ask "scan example.com with CipherHorizon and
tell me what to fix first" to see the whole flow.

## Protocol notes

Specification revision 2026-07-28 through the official Go SDK (v1.8.0), with the earlier revisions
negotiated for older clients. The HTTP transport is stateless Streamable HTTP: no sessions, every request
self-contained, so it sits behind any proxy. There is no OAuth flow: a self-hosted server has one key or
its own accounts, and every client takes a static header. The SSE transport of 2024 is not offered.
