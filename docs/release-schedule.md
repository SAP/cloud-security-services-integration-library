# Release Schedule (DRAFT)

> **Status: DRAFT — working document for team discussion.**
>
> This document proposes a fixed release schedule for the Cloud Security Services Integration
> Library, modeled after the [SAP CAP release schedule](https://cap.cloud.sap/docs/releases/schedule).
> Open points are collected at the bottom.

## Overview

| Release type | Cadence | Content | Breaking changes |
|---|---|---|---|
| **Major** | yearly (proposed: October) | New features, dependency majors, JDK baseline changes | Yes — minimized and documented in a migration guide |
| **Minor** | monthly (active line only) | New features, dependency minor/patch upgrades | No (public API) |
| **Patch** | as needed (all maintained lines) | Critical bug fixes only | No |

All modules of the library are versioned and released **in lockstep** (one version per release,
no independent module versions — see `CLAUDE.md`).

Library consumers can rely on this schedule for planning:

- **Adopt new majors as soon as reasonable** — former majors receive critical bug fixes only.
- **Track the latest minor of the active major** for ongoing development.

## What we already do today (de-facto practice)

The proposal below formalizes what the team already practices:

- **Active line on `main`** — currently `4.x` (latest: 4.1.2).
- **Maintenance line on `main-3.x`** — currently `3.7.x`, receiving backported critical fixes and
  dependency maintenance releases (e.g. `Chore/3.x update dependencies maintenance`).
- **Release process** (`CLAUDE.md`): CHANGELOG entry → version bump across root POM, module POMs
  and READMEs → release PR (`Release x.y.z`) → tag `vx.y.z` → CI `release` profile publishes to
  Maven Central.
- **Migration guide convention for majors** — see `MIGRATION_4.0.md`.
- **Dependabot** handles dependency minor/patch updates (grouped, on `main` and `main-3.x`).

## Major Releases (yearly)

New **major versions** are released **once a year** in a fixed month (proposed: **October**, see
open questions). The schedule gives consumers a reliable basis for planning adoption.

Major version upgrades *may* incorporate **breaking changes** to the public API, but we will
avoid that as much as possible. Breaking changes are:

- done for good reason only (e.g. new Spring Boot / Spring Security major, raised JDK baseline,
  removal of deprecated API),
- documented in a **migration guide** (`MIGRATION_x.0.md`) and in the release notes,
- announced **several months in advance** (issue + note in the README).

Major releases are typically driven by the release and maintenance schedule of crucial
dependencies. For this library the relevant drivers are:

- **Spring Boot / Spring Security** — the library ships modules for different Spring lines
  (`spring-security` for the current line, `spring-security-3` for the previous line),
- **JDK baseline** (currently: Java 17),
- major dependency changes in `java-api` / `token-client` / `java-security`.

Only **one** major version has *active* status at a time. New features are provided in the active
major only.

## Monthly Minor Releases

The active major is updated with **monthly minor releases**:

- **No breaking changes** to the public API. Minor releases may change undocumented, private
  interfaces.
- Content: new features, dependency minor/patch upgrades (via Dependabot), minor fixes.
- Each minor release follows the standard release process (CHANGELOG entry, version bump,
  release PR, tag).

**In between official releases** we may publish patch versions as needed (e.g. urgent fixes).

## Patch Releases / Maintenance Cycles

A **patch release** receives **critical bug fixes only**.

- On the **active** line: patch releases are cut as needed for urgent hotfixes (current
  practice — e.g. `4.1.1`, `4.0.8`).
- On **maintenance** lines: patch releases are cut as needed for critical fixes, backported from
  the active line or fixed directly on the maintenance branch.

**Definition of critical** (borrowed from CAP):

- security incidents, and
- bugs that show up in customer usages of already developed and shipped applications.

Gaps or bugs detected in *new* development with functional enhancements are **not** considered
critical and are therefore not backported to maintenance lines.

A release in *maintenance* status **does not** receive:

- new features,
- dependency major upgrades,
- fixes for minor bugs and gaps,
- new public API.

## Status Definitions

### Active

The current major (currently `4.x`, developed on `main`). Receives:

- monthly minor releases (new features, dependency updates),
- patch releases for urgent fixes,
- all kinds of fixes.

### Maintenance

When a new major is released, the **previous** major enters *maintenance* status (currently:
`3.x` on `main-3.x`). It receives **critical bug fixes only** for a maintenance window of
**proposed 12 months** after the new major's release. It keeps:

- its dependency baseline (only security/patch-level dependency updates),
- its JDK baseline.

### End of Life

After the maintenance window, the former major reaches *end of life* and **receives no fixes at
all** (bug reports are closed as rejected by default). Projects sticking to an EOL version must
freeze their environment:

- no dependency updates beyond patch level,
- no new features, no changes beyond hotfixes and cosmetic work.

With yearly majors and a 12-month maintenance window, **at most two majors are maintained in
parallel** (active + one in maintenance). Example transition when `5.0` ships:

| Line | Before 5.0 | After 5.0 |
|---|---|---|
| 5.x | — | active |
| 4.x | active | maintenance (12 months) |
| 3.x | maintenance | **end of life** |

## Adoption Strategy

- Projects using the library are encouraged to run on the **latest minor of the active major**
  during development.
- After a new major ships, migrate within **one quarter** (proposed) — the previous major is in
  maintenance and receives critical fixes only after the maintenance window is over.
- Near-term go-lives should not be endangered by adopting a new major; deployed applications may
  keep running on their frozen versions.

## Open Questions

1. **Month for the yearly major?** Proposed: October. Alternatives: align with the Spring Boot
   release cycle, or a fixed quarter (e.g. start of Q4).
2. **Maintenance window:** 12 months (like CAP) or longer for the 3.x line, which still has
   customer usage?
3. **Monthly minor: strict calendar date or "at least monthly if there is a releasable change"?**
   A strict date gives the strongest planning basis but may produce empty releases.
4. **Backport criteria:** who decides what is "critical" for a maintenance line (library owner
   on-call? team vote?), and is there a checklist?
5. **Deprecation policy:** should public API be deprecated for at least one minor release before
   it can be removed in a major (and tracked in the CHANGELOG)?
6. **EOL communication:** README note, GitHub issue/discussion, email to subscribers? Where is
   the schedule published externally (repo README, product documentation)?
7. **Release date convention:** e.g. "releases happen the last week of the month" vs. on demand?

## Proposed Timeline (illustrative)

Assuming the proposals above (October majors, 12-month maintenance window):

| Date | Event |
|---|---|
| now | `4.x` active on `main` (4.1.x), `3.x` in maintenance on `main-3.x` (3.7.x) |
| monthly | minor releases on `4.x` (4.2.0, 4.3.0, …) |
| Oct 2026 (proposed) | `5.0.0` released → `4.x` enters maintenance, `3.x` reaches end of life |
| Oct 2027 (proposed) | `6.0.0` released → `5.x` enters maintenance, `4.x` reaches end of life |
