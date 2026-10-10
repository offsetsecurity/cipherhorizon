# Audit and 0.1.0 readiness

A structured review of the whole product before its first release, run as roles that hand work to each other:
review, product decision, design, build, test, release. Read in order.

| # | Document | Role | Question it answers |
|---|---|---|---|
| 01 | [Security audit](01-security-audit.md) | Security reviewer | What protects the product, and where does it fall short? |
| 02 | [Usability and UI audit](02-usability-audit.md) | UX reviewer | Can a first-time user tell where they are and what to do next? |
| 03 | [Gap analysis](03-gap-analysis.md) | Product analyst | What is built but not connected, and what is missing? |
| 04 | [UI direction](04-ui-direction.md) | Design lead | What should it feel like, and what changes? |
| 05 | [PM decision](05-pm-decision.md) | Product manager | What is approved, deferred or blocked, and what proves it done? |
| 06 | [QA report](06-qa-report.md) | QA | What was actually tested, and what was not? |
| 07 | [Release gate](07-release-gate.md) | Release manager | Is it ready, and what remains for the owner? |

## The result in one paragraph

No critical or high security finding. Two medium ones (a world-readable database file, and any token being
accepted) and five low ones were fixed. The larger gap was usability: half the product (host inventory) was invisible
to a new user and the collector's own coverage statement never reached the screen. Both are fixed, the interface
was given a calmer visual pass, and the change is verified by 371 Go tests, a 33-check live security script and a
58-check browser journey. What is *not* verified, and is said so in every place it matters: Linux and Administrator
collector runs, the release pipeline, and POSIX file modes (they run in CI once the repository exists).

Finding IDs (`SEC-`, `UX-`, `GAP-`) are stable and are referenced from the code, tests and changelog.
