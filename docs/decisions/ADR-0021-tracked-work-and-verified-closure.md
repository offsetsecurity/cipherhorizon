# ADR-0021: Tracked work runs on workflows defined as data, and only the product's own evidence closes it as verified

**Status:** accepted · **Date:** 2026-11-18 · **Context:** PRD-023, ARCH-001 (internal product documentation)

## Context

CipherHorizon finds what is wrong and orders it (findings, readiness, standards, the system ranking). Nothing
after that point existed: no owner for a change, no due date, no approval, no record that the change was made,
and no check that it worked. Organisations run that part of the job in their own process, and those processes
differ: some need an approval before a certificate is replaced, some approve after an emergency, some cannot
verify a vendor's fix at all.

Two things had to be decided: what runs the process, and what is allowed to say a change is done.

Engines considered (licences checked 2026-11-18): Temporal (MIT; a separate server cluster and database,
workflows written as code), `cschleiden/go-workflows` (MIT; durable execution, workflows as code),
`qmuntal/stateless` (BSD-2-Clause) and `looplab/fsm` (Apache-2.0; in-memory state machines configured in code).

## Decision

1. **A small state machine of our own, `internal/workflow`, persisted in SQLite.** A transition happens when a
   person acts, days or weeks apart: the state is a row (`work_items`), the history is the append-only
   `audit_log`. There is no long-running process to resume, so durable-execution engines add a server and a
   programming model for nothing; the in-memory FSM libraries give transitions but none of what matters here
   (approvals, evidence, verification, persistence).
2. **A workflow template is data** (JSON): stages, transitions, the subjects it applies to, the role a
   transition needs, the fields it requires (note, evidence, end date), whether it is an approval, whether it
   needs verification. Eight templates are built in; an administrator can add their own or a new version of one
   (`POST /api/v1/workflows`). A piece of work keeps a copy of the template it was created with, so changing a
   template never changes work already under way.
3. **Markers keep custom workflows comparable.** Each stage may carry one marker from a fixed vocabulary:
   `requested`, `approved`, `executed`, `reported`, `verified`, `complete`, `exception`, `cancelled`. Lists,
   filters and (later) metrics read markers, never stage names.
4. **The engine enforces what a template cannot switch off:**
   - a stage marked `verified` is entered only by a transition that requires verification, and that
     transition is allowed only when the product's own verification says *verified*;
   - a stage marked `approved` is entered only by an approval, given by a signed-in person who did not request
     the work and has not approved it already; with sign-in off every caller is the same anonymous operator or
     the automation token, so approvals are refused;
   - a stage marked `exception` needs a note and an end date in the future;
   - a stage that says the change was made or the work is done (`executed`, `reported`, `verified`,
     `complete`) cannot be entered while a prerequisite is unfinished;
   - a template whose transitions verify may only name subjects the product can verify.
5. **Verification is computed, never entered.** Its baseline is the moment the work last entered an
   `executed` or `reported` stage. After that moment:
   - *finding on an endpoint or host*: the latest complete scan (or host upload) no longer has the finding; an
     incomplete scan proves no absence;
   - *certificate*: every scanned endpoint that presented it as its leaf before the change now presents a
     different leaf that is valid for longer; a certificate no endpoint ever presented cannot be verified this
     way;
   - *readiness target on an endpoint*: the latest scan's level is at or above the target.
   The answer is one of `verified`, `not-verified`, `waiting` (no evidence yet) and `not-verifiable`, with the
   scan it rests on. A change the product cannot observe may be closed as `complete`; it is never shown as
   `verified`.

## Consequences

- No new dependency. The workflow package is pure (no store, no network) and fully unit-tested.
- Approval separation of duties requires sign-in; a server run with the automation token only cannot approve,
  which is stated in the error and in the documentation. A team that does not want approvals uses or writes a
  template without them.
- Work is cancelled, never deleted, so its history in `audit_log` stays complete.
- The finding triage status `accepted-risk` (migration 3) keeps its old meaning (no end date); a time-limited
  exception is a workflow's `exception` stage.
- Connectors that execute changes (a later milestone) will only be called from a transition a person made on
  approved work; they will not be able to enter a `verified` stage on their own report.
