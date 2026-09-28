# PatchLab Internal: estate maintenance design

Status: proposal, 2026-09-28. Builds on [ESTATE_SURVEY.md](ESTATE_SURVEY.md).

## 1. Goal

Keep six repositories healthy with evidence instead of guesswork:

| Repo | Ecosystems | Tests need |
|---|---|---|
| latticeiq | Python, npm, Go | Postgres |
| streamly-security-core | npm | — |
| caer | npm (2 packages) | — |
| sentinel | Python, npm | — |
| sentry | Cargo | — |
| subsovereign (StreamlyApps) | npm (9 packages), Gradle, Swift | Postgres 13+, Redis |

PatchLab Internal already answers "did this change break anything, or was it
already broken?" by running the same checks before and after a change in a
disposable sandbox. This design adds the estate layer on top of that engine:
knowing what each repo needs, finding what should change, testing each change
that way, and handing a person a ready-to-review result.

The four capabilities, in build order:

1. **Dependency and security updates:** find advisories, build the fix, test
   it before and after, open a draft PR with the report.
2. **Build health:** a scheduled "does it still build and pass its own
   tests" run for every repo, independent of each repo's own CI.
3. **Consistency and drift:** rule checks across the estate (runtimes,
   lockfiles, licences, audits, SDK/sample toolchains).
4. **Estate dashboard:** one page showing all of the above per repo.

### Non-goals (for now)

- **No merging, no deploying.** The tool opens draft PRs at most; people
  review and merge.
- **Never touches production** or real credentials. Tests run with fixtures
  and dummy secrets, as latticeiq's CI already does.
- **No macOS builds in v1.** subsovereign's iOS/tvOS SDK is reported as
  "not verified", never silently passed.
- **Doesn't replace each repo's CI.** It's a second, independent check and
  the thing that proposes changes.

## 2. Principles

Inherited from PatchLab, plus three for the estate:

1. **Differential by default.** A change is judged on what it breaks
   compared with the same checks just before it, so a repo with failing
   tests can still be maintained.
2. **The diff that was tested is the diff that is proposed.** The PR
   contains exactly the bytes the sandbox verified, lockfile included.
3. **Say what wasn't verified.** Missing tests, skipped platforms and
   unauditable packages appear in the report as findings, not silence.
4. **Humans approve.** The tool may open draft PRs; it never merges, force
   pushes, or pushes to a default branch.
5. **Boring dependencies.** The core stays standard-library Python plus the
   ecosystems' own CLIs (npm, pip-audit, cargo, go), run inside containers.

## 3. Architecture

```
            estate.toml  (repos, packages, checks, sidecars, policy)
                 │
  ┌──────────────┼───────────────────────────────────────────────┐
  │  estate layer (new: patchlab_internal/estate/)                │
  │                                                               │
  │  sync ──► scan ──► propose ──► test ──► publish               │
  │  clone    audits   build the   run the  draft PR / digest /   │
  │  or pull  outdated diff in a   existing report + state        │
  │  repos    drift    container   engine                         │
  └──────────────────────────────┼────────────────────────────────┘
                                 │  one Config + one source Patch per change
  ┌──────────────────────────────▼────────────────────────────────┐
  │  existing engine: provision → deploy → baseline → apply →     │
  │  verify → compare → rollback → report → teardown              │
  │  + new: sidecar services, repo checkout deploy, JUnit adapters│
  └───────────────────────────────────────────────────────────────┘
                                 │
                   state/ (JSON per run) ──► web UI: Estate page
```

### 3.1 The estate manifest

One file, `estate.toml`, describes every repo. A repo has one or more
**packages** (a directory with its own manifest and lockfile), and each
package has the checks that prove it still works. The checks are the
existing `[[checks]]` format, so everything the engine already does
(per-test JUnit comparison, critical vs. non-critical, timing) applies
unchanged.

```toml
[defaults]
schedule.health = "daily 02:00"
schedule.audit  = "daily 03:00"
publish = "draft-pr"            # or "report-only"
workdir = "/var/lib/patchlab-internal/estate"

[[repo]]
name   = "subsovereign"
url    = "https://github.com/StreamlyApps/subsovereign"
branch = "main"

  [[repo.package]]
  path      = "backend"
  ecosystem = "npm"
  image     = "node:24-bookworm-slim"   # what the tool tests on, not what the repo ships
  setup     = ["npm ci"]
  sidecars  = ["postgres:16", "redis:7"]
  env       = { DATABASE_URL = "postgres://test:test@postgres/test", REDIS_URL = "redis://redis:6379" }

    [[repo.package.checks]]
    name = "typecheck"
    run  = "npm run build"
    category = "build"

    [[repo.package.checks]]
    name = "unit-tests"
    run  = "npx vitest run --reporter=junit --outputFile=/tmp/junit.xml --exclude '**/audit-chain.test.ts'"
    results = "junit:/tmp/junit.xml"

    [[repo.package.checks]]
    name = "audit-chain"
    run  = "npm run test:chain"

  [[repo.package]]
  path      = "sdk-ios"
  ecosystem = "swift"
  unsupported = "macOS runner required"   # always reported as not verified

[[repo]]
name = "latticeiq"
url  = "https://github.com/MIIMAGINELabs/latticeiq"

  [[repo.package]]
  path      = "backend"
  ecosystem = "python"
  lockfile  = "requirements-lock.txt"
  image     = "python:3.14-slim"
  setup     = ["pip install -r requirements-lock.txt"]
  sidecars  = ["postgres:18-alpine"]

    [[repo.package.checks]]
    name = "migrations"
    run  = "alembic upgrade head && alembic downgrade base && alembic upgrade head && alembic check"

    [[repo.package.checks]]
    name = "pytest"
    run  = "python -m pytest tests/ -q --junitxml=/tmp/junit.xml"
    results = "junit:/tmp/junit.xml"
```

`estate validate` checks the manifest the way `validate` checks a config
today. The first version of the manifest is written by hand from the
survey's §3 table; detection can come later.

### 3.2 Engine changes

Small, general changes. Nothing estate-specific goes into the engine.

| Change | Where | Why |
|---|---|---|
| **Sidecar services.** `[[sidecars]]` (image, env, health command) start on a per-run Docker network next to the sandbox, carry the same run label, and are removed by teardown and `gc`. | `sandbox.py`, `linux.py`, `config.py` | latticeiq needs Postgres; subsovereign needs Postgres and Redis. Today there's one container per target. |
| **Repo checkout as deploy source.** A `[[deploy]]` can name a git checkout at a commit; the run records the commit SHA. | `config.py`, `runner.py` | Reports and PRs must say exactly what was tested. |
| **JUnit adapters documented per ecosystem:** pytest `--junitxml`, vitest `--reporter=junit`, jest-junit, `gotestsum --junitfile`, `cargo nextest` (JUnit output via a profile in `.config/nextest.toml`). | docs + examples | Per-test before/after comparison instead of pass/fail per command. |
| **"Baseline only" mode.** `run --no-patch`: provision, deploy, run the checks once, report. | `runner.py`, `cli.py` | Build health (§4.2) is a baseline with nothing to compare against. |
| **"Not verified" findings.** A package marked `unsupported` produces an `info` finding naming what wasn't checked. | `compare.py`, `report.py` | Principle 3. |

Dependency changes need **no new patch kind.** They're tested as `source`
patches (a unified diff), which already have `git apply`, a reverse-diff
rollback, and `--verify-rollback`.

### 3.3 State

Every scan and run writes JSON under `state/<repo>/<date>/`: advisories
found, proposals made, run reports (the engine's `report.json`), and drift
findings. The dashboard and the daily digest read only these files. SQLite
can replace the directory tree later without changing the producers.

## 4. The four capabilities

### 4.1 Dependency and security updates

**Scan** (per package, in a container of that ecosystem):

| Ecosystem | Advisories | Outdated |
|---|---|---|
| npm | `npm audit --json` (all and `--omit=dev`) | `npm outdated --json` |
| Python | `pip-audit -r <lockfile> -f json` | `pip index versions` / `pip list --outdated` |
| Cargo | `cargo audit --json` | `cargo outdated` (optional) |
| Go | `govulncheck -json ./...` | `go list -m -u all` |

The runner host needs network access to each advisory database
(`registry.npmjs.org`, OSV/PyPI, the RustSec index, `vuln.go.dev`). The last
one is blocked from the environment the survey ran in; it must be allowed on
the real host.

**Propose.** Group advisories by package directory and dependency. For each
group, choose the **smallest version that fixes every advisory**, and
classify the change:

- **patch/minor within the declared range**: lockfile-only update
  (`npm update <pkg>`, re-lock for pip, `cargo update -p <crate>`);
- **major or out of range**: manifest and lockfile update, labelled
  `breaking-risk` in the PR and report;
- **no fixed version** (e.g. `accelerate`): report only.

The proposer runs the ecosystem tool **inside a throwaway container** on a
clean checkout, then captures `git diff` as the patch file. That diff is
what the engine tests and what the PR contains.

**Test.** One engine run per proposal: baseline checks → apply the diff →
reinstall (`setup` re-runs) → the same checks → compare → reverse the diff →
check again (`--verify-rollback`). The re-audit after applying confirms that
the advisory is actually gone.

**Publish.**

| Verdict | Action |
|---|---|
| PASS | Draft PR on branch `patchlab-internal/<package>/<dep>-<version>`, the report as the PR body (summary) and attachment (full HTML). |
| WARN | Draft PR, with the warnings at the top of the body. |
| FAIL | No PR. Goes into the daily digest with the regressions the report lists, for a person to decide. |
| ERROR | No PR. Digest entry marked "couldn't test" with the stage that failed. |

One open PR per package and dependency: if a newer fix appears, the tool
updates its own branch instead of opening another PR. It never touches
branches it didn't create.

### 4.2 Build health

A scheduled `--no-patch` run per package on the default branch's latest
commit, using the same manifest checks. Results over time give:

- **broken:** a check that passed on the previous run fails now, naming
  the commits in between;
- **flaky:** a failure that passes on one immediate re-run, tracked per
  test so a flaky test is recognised, not re-reported daily;
- **not tested:** packages with no checks, or `unsupported`, are listed
  every day so the gap stays visible.

This is what catches the two situations the survey found: sentry has no CI
at all, and subsovereign's CI hasn't run since 8 September.

### 4.3 Consistency and drift

Rules are data (`rules.toml`), evaluated against each checkout. No sandbox
is needed.

| Rule | Example today |
|---|---|
| Runtime is supported (Node, Python, Alpine, Go, Rust edition against an end-of-life table kept in the repo and refreshed monthly) | Node 20 in subsovereign, caer, sentinel |
| Every package has a committed lockfile | sentinel's dashboard |
| Dependency audit runs on a schedule, not only when a path changes | sentinel's `pip-audit` |
| LICENSE file present and matches the manifest's declared licence | sentry declares Apache-2.0, no file |
| SDK and its sample use the same toolchain versions | subsovereign Android: Kotlin 2.0.21 vs 2.2.0 |
| No stray empty or oversized files at the root | subsovereign's `invalid` |
| CI has run on the default branch in the last N days | subsovereign |

Drift findings are **report-only** in the first versions. Some fixes are
mechanical (bumping a Docker base image), but they change what ships, so
they become proposals only once the runtime bump itself has been tested like
any other update (§4.1).

### 4.4 Estate dashboard

A new **Estate** page in the existing web front end
(`patchlab_internal_web`), built from `state/`:

- one row per repo and package: last health result, open advisories by
  severity, open proposals and their verdicts, drift findings, last CI run;
- drill-down to each run's existing HTML report;
- a daily digest (Markdown) written to `state/digest/<date>.md`, which can
  also be posted to a channel once one is chosen.

The web UI keeps its current security model: localhost plus a per-session
token.

## 5. Security and permissions

- **GitHub access:** read on all six repos; write only to create branches
  prefixed `patchlab-internal/` and open draft PRs. A GitHub App installed on
  the two organisations is preferred to a personal token, since it can be
  scoped to these repos and its actions are clearly attributed.
- **Never:** push to a default branch, force-push, merge, approve, or edit
  a branch it didn't create.
- **Sandbox network:** open while dependencies install (the registries);
  test phases can run with `network = "none"` plus the sidecar network for
  packages whose tests don't need the internet.
- **Secrets:** none are passed into sandboxes. Test env vars are fixed
  dummy values in `estate.toml`; real credentials are rejected by
  `estate validate` if they match known secret formats.
- **Supply chain:** installs use the lockfile (`npm ci`, `pip install -r
  <lock>`, `cargo --locked`). A proposal that adds a new package, rather than
  changing a version, is flagged in the PR.

## 6. Where it runs

A Linux host with Docker, reachable to GitHub and the package registries,
running the tool from a systemd timer (or cron): `estate sync`, then `scan`,
`health` and `propose` on the schedules in `estate.toml`. A self-hosted
runner is preferable to GitHub-hosted Actions because sidecars and many
sequential sandbox runs are cheaper and faster on a dedicated machine, and
because subsovereign's Actions minutes are currently not running.

Rough load: 6 repos, ~15 packages. A daily health pass is ~15 sandbox runs;
a proposal is one run with rollback verification. A 4-CPU / 16 GB host
covers this with room to spare.

## 7. Milestones

### M1: subsovereign nodemailer, end to end (first)

The survey's most important finding, and a real test of the design:
nodemailer 6.x → 10.0.12 in `subsovereign/backend` is a production security
fix across a major version. The backend has a suite that exercises it
(`platform-relay.test.ts` sends real mail through an in-process SMTP sink),
and it needs Postgres and Redis sidecars.

Work: sidecars (§3.2), repo-checkout deploy, the `estate.toml` entry for
`subsovereign/backend`, the npm proposer for one dependency, report-only
publishing.

**Done when:** `patchlab-internal estate propose subsovereign/backend
nodemailer` produces a diff; the engine runs the backend's typecheck and
vitest suites before and after with Postgres and Redis; the report shows the
per-test comparison, rollback verification, and the re-audit result; nothing
is left running afterwards.

### M2: security updates for all six repos, report-only

Scanners for npm, Python, Cargo and Go; the manifest for all six repos;
proposals and test runs for every current advisory in the survey (§4).
Daily digest.

**Done when:** each advisory in the survey has either a tested proposal
with a verdict or a stated reason why not.

### M3: build health

`--no-patch` runs on a schedule, flaky detection, the "not tested" list.

**Done when:** a week of daily runs for all six repos, with sentry and
subsovereign covered despite having no working CI.

### M4: draft PRs

GitHub App, branch naming, one PR per package and dependency, PR body from
the report, updating its own branches.

**Done when:** a PASS proposal becomes a draft PR that a person can review
and merge with no local steps.

### M5: drift rules and the Estate page

`rules.toml` with the rules in §4.3, the Estate page, and the digest on the
page.

**Done when:** the dashboard shows the survey's findings, regenerated
daily, with no hand-maintained tables.

## 8. Decisions needed

1. **Runner host:** which machine runs the tool (M1 can run on any Docker
   host; M3 onwards needs one that's always on).
2. **GitHub access for M4:** a GitHub App on MIIMAGINELabs and StreamlyApps
   (recommended), or a fine-grained token.
3. **Where the digest goes:** a file only, or also email or a chat channel.
4. **subsovereign's Actions:** someone with StreamlyApps account access
   needs to find out why no job has reached a runner since 8 September. The
   tool can't fix that, but it shouldn't wait for it either.
