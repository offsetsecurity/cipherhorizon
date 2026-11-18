# ADR-0022: Standards documents and their dated milestones are a catalog of data, separate from the checks

**Status:** accepted · **Date:** 2026-11-18 · **Context:** PRD-023, PRD-017, PRD-021 (internal product documentation)

## Context

The transition dates the product acts on (NIST IR 8547: quantum-vulnerable public-key algorithms deprecated
after 2030 and disallowed after 2035; the United States federal dates that IR 8547 quotes from Executive Order
14412 and OMB M-26-15) were Go constants in `internal/eval` and a table in the Help page. Nothing tied them to
a document's status (final or draft), its date or its address, and two of them had drifted: the certificate
rule treated "disallowed after 2035" as starting on 1 January 2035.

Standards also change on their own schedule (SP 800-131A Rev. 3 is still a draft; FIPS 206 is not final), and
organisations follow different documents.

## Decision

1. **`internal/policy` holds an embedded JSON catalog**: documents (publisher, identifier, title, edition,
   status `final` / `draft` / `withdrawn` / `superseded`, date, HTTPS URL, provenance), milestones (document,
   clause, plain text, effect `deprecated` / `disallowed` / `required` / `recommended`, `after` or `by` a date,
   the algorithm families or strength it applies to, scope `general` / `us-federal` / `us-federal-hva`,
   provenance) and profiles (named sets of milestones).
2. **The catalog is validated when it loads and in tests**: unique identifiers, known vocabulary, valid dates,
   HTTPS addresses, provenance present, profile references resolve, and **no deprecation, disallowance or
   requirement rests on a draft**. A draft can be listed so readers see it exists.
3. **Checks stay code.** A clause of a standard that the evaluation judges (PRD-017) is logic over a scan and
   remains in `internal/eval`; the catalog is the place for what is a fact about a document: its status, its
   dates, what it applies to.
4. **The evaluation reads its dates from the catalog.** "After 2030" is after the last instant of 31 December
   2030; "after 2035" is after the last instant of 31 December 2035.
5. `GET /api/v1/policy/catalog` serves it; it carries its own version string.

## Consequences

- A certificate valid until a day in 2035 is reported as outliving the 2030 deprecation (medium), no longer as
  outliving the 2035 disallowance (high). Certificates valid into 2036 or later are unchanged.
- Updating a date or a document's status is a data change with a test, not a code change.
- Entries whose primary document could not be read (the NSA CNSA 2.0 advisory refuses automated download) are
  listed without dated milestones until someone transcribes them from the document.
- Later milestones read profiles to choose which documents apply to a system, and recommendations cite catalog
  entries.
