# ADR-0014: Keep the product name CipherHorizon

- **Status:** Accepted (pending owner-run trademark clearance, which is a launch gate, not a build gate)
- **Date:** 2026-09-26
- **Deciders:** Product Manager, Security Architect
- **Evidence:** [RESEARCH-003 §1](../product/RESEARCH-003-ecosystem-standards-and-design-inputs.md)

## Context

The product owner said CipherAtlas or Cryptograph "both look fine". Research found an existing GitHub project called CipherAtlas in the same category, and "Cryptograph" to be a crowded, generic, hard-to-search term.

## Decision

Keep **CipherHorizon**. This deliberately departs from the owner's stated preference; the reason is the same-category collision, and the owner can overrule it.

## Consequences

- No rename work now. The module path is still the placeholder `github.com/example/cipherhorizon` (`scripts/set-owner.sh` fixes that at publication).
- Namespace registration of `cipherhorizon:*` with the CycloneDX property taxonomy waits until trademark clearance, because a rename after registration is costly.
- A rename must stay mechanical: module path, binary names, the `cipherhorizon:` property prefix, the `CIPHERHORIZON_*` environment variables, documentation. PRD-003 REQ-REL-3 requires that these be reachable by one documented procedure.
- **Owner actions before public launch:** trademark search in intended jurisdictions; domain, GitHub organisation and package-name availability.
- This research is a web search, not legal clearance. It says nothing about pending filings or non-English markets.
