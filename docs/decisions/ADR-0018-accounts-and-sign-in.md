# ADR-0018 — Accounts and sign-in

Status: accepted, 2026-10-05.

## Context

Until now the server had one optional shared bearer token and, on loopback, no authentication at all. The owner:
*a secure login is missing; it would contain sensitive information.* That is right. The database is a map of an
organisation's weak cryptography: which endpoints accept broken protocols, which machines run vulnerable
libraries, and the raw inventories. A single shared secret gives no accountability. It cannot be taken away from
one person, and if the browser keeps it in storage, a script can read it.

## Decision

1. **Accounts with three roles**, enforced in one place (`Server.authorize`) for every route:
   - *administrator*: everything, including accounts and the sign-in log;
   - *analyst*: scan, upload, import, triage, edit systems;
   - *viewer*: read and download only.

   The last enabled administrator cannot be demoted, disabled or deleted.
2. **Passwords**:
   - Stored as PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP), a 16-byte salt and a 32-byte key, using Go's
     standard library `crypto/pbkdf2`. It is FIPS-approved and needs no new module. Hashes made with fewer
     iterations are upgraded at the next sign-in.
   - Policy (NIST SP 800-63B): 12 to 256 characters, no composition rules, refused if it contains the username,
     repeats one character or is a well-known password.
   - Hashing runs at most four at a time, so a burst of attempts cannot starve the scanner.
3. **Sessions**:
   - A random 256-bit token in a cookie that is `HttpOnly`, `SameSite=Strict` and `Path=/`, and `Secure` when the
     browser reached the server over HTTPS (TLS listener, or `X-Forwarded-Proto: https` from a proxy).
   - Only the token's SHA-256 is stored, so a copy of the database signs nobody in.
   - A new token at every sign-in.
   - A session ends after 30 minutes idle and after 12 hours in any case (both adjustable), at sign-out on the
     server, and when the account is disabled or its role changes.
   - A password change ends the account's other sessions.
4. **Guessing**:
   - One message for a wrong username or a wrong password, with the same hashing work for both.
   - Five consecutive failures lock the account for 15 minutes. Only someone who also has the right password
     learns that it is locked.
   - Twenty failures from one client address within 15 minutes get `429`.
   - Every attempt is recorded in a sign-in log (administrators; capped at 5,000 lines) and the server log.
     Neither ever holds a password.
5. **Forgery**: the existing guard applies to sign-in too: a required custom header, an Origin check,
   Sec-Fetch-Site and JSON-only bodies. Together with `SameSite=Strict`, a foreign page can neither sign someone
   in (login CSRF) nor act as them.
6. **First run**: until an account exists, the server prints a one-time **setup code** in its log. The first
   administrator can be created only with it, so whoever merely reaches the port cannot claim the server. The code
   stops working once an administrator exists, and the insert is atomic, so two racing set-ups cannot both
   succeed.
7. **Administrator-made accounts** get a temporary password, which must be replaced before anything else.
8. **Recovery from the console**: `cipherhorizon user list|add|reset-password|unlock`. The password is read from
   standard input, never from an argument.
9. **Transport**:
   - `--tls-cert/--tls-key` serve HTTPS (TLS 1.2 and 1.3; Go offers X25519MLKEM768 first).
   - Beyond loopback, plain HTTP is refused unless `--plain-http` declares a TLS-terminating proxy in front or a
     host-only published port.
10. **Kept**:
    - The automation token (`--token`) still works as a bearer token for scripts and CI, acting as an analyst. The
      browser no longer asks for it or stores it.
    - `--no-login` keeps the single-user loopback mode for a laptop. It is refused on a network address.

## Consequences

- Sign-in is on by default. An existing install shows the setup screen at its next start, and the setup code is
  in its log.
- New tables `users`, `sessions` and `auth_events` (migration 9). The usual pre-migration backup is kept.
- Not done yet: single sign-on (OIDC/SAML), a second factor (TOTP or WebAuthn), and per-user API tokens. A reverse
  proxy can add SSO or MFA today. The sign-in log is local; a SIEM can read the server log, where every event is
  written too.

## Evidence

- `internal/auth` tests: hashing, policy, tokens, setup code.
- `internal/server/accounts_test.go`: setup, generic errors, lockout, rate limit, roles, the last administrator,
  idle and absolute expiry, password change ending other sessions, the automation token.
- `testing/e2e/security.sh` "sign-in" and "HTTPS" sections (cookie flags, login CSRF, 429, Secure over TLS,
  TLS 1.1 refused).
- `testing/e2e/auth-phase.mjs` (E2E-A.1–A.10) drives all of it through the browser.
