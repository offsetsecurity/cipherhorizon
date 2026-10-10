# r/selfhosted draft

**Title:** CipherHorizon: self-hosted dashboard for TLS posture and post-quantum readiness of everything you run (Docker, one binary, no cloud)

**Body:**

If you run your own mail, LDAP, Postgres or web services, CipherHorizon will tell you how their TLS holds up.
It also tells you whether they already use the post-quantum key exchange that current browsers and OpenSSL 3.5
negotiate.

- **Install:** `docker compose up -d`, then read the one-time setup code from `docker compose logs`. Or one static
  binary for Linux, macOS or Windows.
- **Hardened by default:** the compose file runs read-only, with no capabilities and on loopback. There's a Caddy
  variant for automatic HTTPS, and a sandboxed systemd unit.
- **Covers more than web servers:** STARTTLS for SMTP (25/587), IMAP, POP3, FTP, XMPP, LDAP and Postgres.
- **Over time:** history and scheduled rescans; the activity log shows who changed what.
- **Machines too:** a small readable shell or PowerShell script inventories a machine's crypto packages and
  certificates (it never reads keys), and you upload the text file it writes.
- **Offline:** no telemetry and nothing phones home. Backups with `cipherhorizon db backup`.

Screenshots and docs: `<repo>`. Apache 2.0, made by Offset Security.
