# ADR-0009 — Privilege disclosure warning, and minimise-by-default redaction

- **Status:** Accepted by the user's instruction (2026-09-24: "decide on best way", "should give a warning …
  elevated privileges might be needed"); implemented in L0/L1
- **Date:** 2026-09-24
- **Related:** ADR-0005, ADR-0008

## Context

Two questions were escalated to the user and answered by asking for a decision and a warning:

1. **Redaction (SR-12):** what host and path information should a CBOM contain when it will be uploaded?
2. **Privilege:** the collector defaults to a standard-user run (ADR-0005). The user wants the tool to say plainly
   that a **full result may need elevated privileges**.

## Options considered

Redaction: (a) none; (b) a configurable policy engine; (c) minimise by default with two simple switches.
Privilege: (a) silent; (b) warn only when a denial was seen; (c) always warn below the highest tier, and say what was
seen when it is known.

## Evidence

- Windows standard-user probing worked for most evidence but `Get-Tpm` and protected-process modules were not
  available (Agent 2); a standard-user file walk of `C:\Users\*` will hit denied directories.
- A policy engine needs a consumer to define what to redact; none exists yet (Agent 3 §1.1).
- Paths embed usernames (`C:\Users\alice\…`, `/home/alice/…`); hostnames identify the subject and are needed to
  correlate with `tls scan` endpoints later.

## Decision

**Redaction (always on unless noted):**
1. Emitted paths are **host-relative and normalised** (forward slashes).
2. The **user-profile segment is tokenised**: `Users/<name>/…` → `Users/%USER%/…`; `home/<name>/…` → `home/%USER%/…`.
   Usernames and SIDs are never emitted.
3. **Attributes are allow-listed** per kind (ADR-0005); nothing free-form.
4. The **host name is kept by default** (it is the CBOM subject and the correlation key). A `--redact-host` flag
   (config `host.redact: true`) replaces it with `host-<12 hex>` derived from `SHA-256("cipherhorizon:host:" +
   platform machine id)`, which is stable per machine and does not reveal the machine id. If no machine id can be
   read the run **refuses** rather than emit an unstable label.
5. No general policy engine now; a hook exists for one when a consumer defines the need.

**Privilege disclosure:**
1. Detect the tier: `user` (default), `admin` (Windows elevated token / Unix euid 0).
2. **Whenever the run is below `admin`, print one warning to stderr**, on every run:
   *"running without elevated privileges: results may be incomplete. Administrator (Windows) / root (Linux)
   may reveal more."* If the run counted unreadable locations, the warning includes the count and the scope
   ("N directories could not be read").
3. The CBOM records it: `metadata.properties` `cipherhorizon:privilege-tier` and
   `cipherhorizon:coverage-note`, and each collector's coverage status.
4. The warning is **informational, not an error**: exit code is unchanged (exit 2 remains "result produced but
   incomplete", used when a collector failed or a budget was hit).
5. **The tool never escalates by itself.** Running elevated is the operator's explicit choice, and the same
   read-only, allow-listed rules apply at every tier (an elevated run does not read key material either).

## Why

Minimising by construction needs no configuration to be safe; the warning turns a silent limitation into an
informed choice, which is the point of ADR-0008.

## Trade-offs

Hostnames still leave the machine unless `--redact-host` is used; the warning may be seen as noise on hosts where a
standard-user run is complete (accepted: honesty over quiet).

## Consequences

- Users are told, every time, that completeness may depend on privilege.
- A later customer-defined redaction policy plugs into the hook without changing the data model.
- Tests: warning appears below `admin`; is recorded in the CBOM; usernames never appear; `--redact-host` is stable and
  refuses without a machine id.
