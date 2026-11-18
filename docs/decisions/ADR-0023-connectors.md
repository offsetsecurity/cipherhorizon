# ADR-0023: Connectors act only on approved work, never verify themselves, and hold no secret

**Status:** accepted · **Date:** 2026-11-18 · **Context:** PRD-023, ARCH-001 (internal product documentation)

## Context

Organisations already run tools that issue and deploy certificates and change configuration: ACME clients and
CAs (Let's Encrypt, Smallstep step-ca), cert-manager, OpenBao, cloud certificate services, Ansible, ticketing and
chat. Tracked work (ADR-0021) knows what should change and can verify that it did. Connecting the two is useful,
and dangerous: a connector holds credentials to production systems, can change them, and could report its own
success as fact.

## Decision

1. **A registry describes every connector** (`internal/connector`): what it is for (discovery, issuer,
   deployment, verification, workflow, notification), what it can do, how it authenticates, what it must be
   given, what it cannot do, its licence, and its status. A connector is **available** only when it is
   implemented and tested in this program; everything else is **planned** and shown as planned. The registry is
   served at `/api/v1/integrations` and in Settings.
2. **A connector acts only on a transition a person made on approved work**, never on a schedule of its own and
   never because another system asked. The approval rules of ADR-0021 apply before any connector is called.
3. **A connector cannot verify its own change.** Only the product's scanner and collectors can move work into a
   verified stage; a connector's report of success is recorded as evidence of the `reported` marker at most.
4. **Credentials are references, never values.** A setting names an environment variable or a file of the
   server's; the database never holds the secret, the API never returns it (it says only whether it is set),
   and no log line or error message includes it.
5. **Every outbound call goes through the address guard** of the scanner (no link-local or cloud-metadata
   address, loopback only with `--allow-loopback`), with a timeout, no redirects, bounded retries, and its outcome
   recorded. The scan scope does not apply: a destination an administrator configured is not a scan target.
6. **Library code starts no program (ADR-0004).** A connector that must run one (Ansible) waits for an amendment
   that names the one package allowed to, with fixed argument vectors, no shell, a timeout and an environment
   allow-list.

## Consequences

- The webhook's address is stored in the database (it is configuration an administrator typed), although for
  chat webhooks it is itself a credential: delivery errors record the host only, and the address is shown to
  administrators only. Moving it to a reference is a follow-up.
- In this version two connectors are available: the scanner and collectors (verification, discovery) and the
  webhook (notification, and the simplest workflow integration: a ticketing system can open a change from an
  event). The webhook follows rules 4 and 5: the HMAC secret is an environment variable's name.
- Issuer and deployment connectors (ACME via `golang.org/x/crypto/acme`, already a dependency; step-ca through
  ACME; cert-manager; OpenBao; Ansible) are planned, each to be tested against the real system in a container
  before it is listed as available.
- Execution history per connector call, idempotency keys and an execution-request table arrive with the first
  connector that changes something; the webhook's delivery record (`notifications`) is the first instance.
