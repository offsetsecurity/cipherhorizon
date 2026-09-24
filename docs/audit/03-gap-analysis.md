# 03 · Missing links and gap analysis (pre-0.1.0)

**Role:** Product analyst. *What is built but not connected, and what is missing for someone to use the product from
start to finish?* Each gap has a disposition; the PM decisions are in `05-pm-decision.md`.

## A. Built but not connected (the highest-value gaps)

| ID | Gap | Detail |
|---|---|---|
| GAP-01 | The collector's coverage never reaches the user | The CBOM carries privilege tier, coverage and blind spots; ingestion drops them; no screen shows them. |
| GAP-02 | There is no path from "I have a server" to "I have the collector on a machine" | The Hosts page explains nothing; the distribution docs are the only place the commands live. |
| GAP-03 | Findings from hosts and endpoints are ranked together but nothing says what to do first | The dashboard ranks; it does not advise. |
| GAP-04 | Collector output ends in a file, not a next step | The user must know to upload it. |

## B. Genuinely missing, and cheap

| ID | Gap | Detail |
|---|---|---|
| GAP-05 | A copyable upload command for automation | `curl` needs the `X-Requested-With` header and JSON content type; nowhere is that written. Document one working command. |
| GAP-06 | Version is not visible where a bug report would need it | The sidebar shows it; About shows it; the collector's CBOM records its own version but the Hosts page does not. Show the collector version on the host. |
| GAP-07 | The README's first screen does not say what to do first | A four-line "start here" (scan a server; inventory a machine). |

## C. Missing, and larger (recorded, not scheduled for 0.1.0)

| ID | Gap | Why not now |
|---|---|---|
| GAP-08 | Linux and Administrator-tier host validation | Needs a machine the developer does not have (WSL/Kali) and an elevated shell. Stated in the release notes as *not validated*. |
| GAP-09 | Certificate inventory on hosts (level 3), Windows CNG capability (level 2), policy and bindings (4 to 6) | The evidence-pipeline plan; each level is its own gated release. |
| GAP-10 | Five real crypto libraries the collector does not recognise | Recorded in the level-1 test report. |
| GAP-11 | Signed collector binaries (Authenticode), MSI, `.deb`/`.rpm`, macOS | Needs certificates and a decision on distribution; researched in ADR-0007 and `docs/platform/MACOS_SUPPORT.md`. |
| GAP-12 | Users, roles, audit log, TLS listener | Multi-team story; the single-token model is documented as the limit. |
| GAP-13 | Push agent (collector uploads by itself) | Deliberately excluded to keep the collector network-free (ADR-0011); a separate small uploader is an option later. |
| GAP-14 | Real-owner identity: module path, security contact, first push | Blocked on the user's GitHub username; `scripts/set-owner.sh` is ready. |
| GAP-15 | The release pipeline has never executed | Workflows, cosign, Docker image and `make` were validated only as far as a local GoReleaser snapshot. The first tag will be the real test; the plan is a pre-release. |

## D. Documentation debt

`docs/product` reports predate the host pipeline; the tracked `artifacts/` bundle duplicates `docs/` and holds
regenerated screenshots that show as modified on every E2E run. Decision needed from the owner (keep, or publish only
`docs/`); until then the screenshots stay untracked-by-intent and are not committed with this change.
