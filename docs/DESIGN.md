# PatchLab Internal: estate control plane

Status: M1 and M2 built and run end to end on 2026-09-28; M3 onwards proposed.
Builds on [ESTATE_SURVEY.md](ESTATE_SURVEY.md). Revised after the
[docs review](#appendix-review-items) of the first version.

## 1. Goal

PatchLab Internal is the control plane that keeps six repositories up to date
and tested, with evidence instead of guesswork:

| Repo | Ecosystems | Tests need |
|---|---|---|
| latticeiq | Python, npm, Go | Postgres |
| streamly-security-core | npm | — |
| caer | npm (2 packages) | — |
| sentinel | Python, npm | — |
| sentry | Cargo | — |
| subsovereign (StreamlyApps) | npm (9 packages), Gradle, Swift | Postgres 13+, Redis, the private `@streamly/security-core` |

It runs the lifecycle of every dependency change on its own: **find** what
should change (advisories, drift), **build** the smallest change that fixes it,
**test** that change before and after in a disposable sandbox, **triage** the
result through a gate that fails closed, and **publish** a ready-to-review
result (a report today, a draft PR from M4). Separately, it runs every
package's own checks on a schedule (**health**) and tells a person what broke,
since which commits, and whether it's flaky.

### What "0 failures" means here

The bar is: **nothing broken reaches a managed repo's default branch through
PatchLab Internal.** It holds because of three rules, not because tests are
perfect:

1. PatchLab Internal never merges and never pushes to a default branch. At
   most it opens a draft PR; a person merges.
2. A change becomes a PR only when every item of the gate (§4.1.4) is green,
   and any item that could not be evaluated counts as red.
3. Every PR says what the checks do *not* prove (`not_covered` in the
   manifest) and which platforms weren't built.

What it **cannot** guarantee, stated plainly:

- **A change is only as safe as the tests that cover it.** subsovereign's
  backend suite exercises nodemailer through an in-process SMTP sink, so the
  gate proves the code still sends mail the way the tests expect, not that the
  production relay accepts it. That caveat is printed on every nodemailer PR.
- **Platforms that can't run on a Linux host aren't tested.** subsovereign's
  iOS/tvOS SDK needs macOS. It's reported as "not verified", never passed.
- **Tests that already fail can't catch anything.** Pre-existing failures are
  listed on every PR; a test that fails before and after a change is not
  evidence either way.
- **Advisory databases lag.** A clean audit means "nothing known today".
- **The runner's own integrity.** A compromised runner host could publish a
  bad PR; a person reviewing the PR is the last line.

### Non-goals

- **No merging, no deploying, no pushing to default branches.** Ever.
- **Never touches production** or real credentials. Tests run with fixtures
  and throwaway values, as each repo's CI already does.
- **Doesn't replace each repo's CI.** It's a second, independent check and the
  thing that proposes changes.

## 2. Principles

1. **Differential by default.** A change is judged on what it breaks compared
   with the same checks just before it, so a repo with failing tests can still
   be maintained.
2. **The diff that was tested is the diff that is proposed.** The PR contains
   exactly the bytes the sandbox verified, lockfile included, and nothing else:
   npm's reformatting of `package.json` is undone so only the dependency line
   changes (§4.1.2).
3. **Smallest change that fixes everything known.** The lowest major version
   with no known advisory, newest release within it; a bigger jump only if the
   smaller one doesn't audit clean.
4. **Fail closed.** Anything the gate can't evaluate blocks the change.
5. **No credentials in sandboxes.** Private dependencies come from host-side
   mirrors (§5.2); checks run with no route out (§5.3).
6. **Say what wasn't verified.** Missing tests, skipped platforms, stubbed
   services and pre-existing failures appear in the report and the PR.
7. **Humans approve.** Draft PRs at most.
8. **Boring dependencies.** Standard-library Python plus the ecosystems' own
   CLIs, run inside containers.

## 3. Architecture

```
                         estate.toml
       repos · packages · checks · sidecars · mirrors · not_covered
                              │
┌─────────────────────────────▼──────────────────────────────────────────────┐
│ estate layer  (patchlab_internal/estate/)                                  │
│                                                                            │
│  sync ─► scan ─► propose ─► test ─► triage ─► publish        health        │
│  host    npm     tool       engine  gate:     report,        engine run    │
│  git     audit   container  run     READY /   pr.md          --no-patch,   │
│  mirrors (lock-  lock-only, ×1-2    REVIEW /  (draft PR      recheck new   │
│          only)   no scripts         BLOCKED / from M4)       failures      │
│                                     INCONCL.                               │
└─────────────────────────────┬──────────────────────────────────────────────┘
                              │ one Config + one source Patch per change
┌─────────────────────────────▼──────────────────────────────────────────────┐
│ engine: provision (+sidecars, private net) → deploy (+mirrors) → install → │
│ baseline → apply → install → verify → compare → rollback → install →       │
│ verify-rollback → report → teardown (sandbox, sidecars, network)           │
└─────────────────────────────┬──────────────────────────────────────────────┘
                              ▼
               state/ (JSON per run) ──► digest (Markdown) ──► Estate page (M5)
```

### 3.1 The estate manifest

[`estate.toml`](../estate.toml) describes every repo. A repo has one or more
**packages** (a directory with its own manifest and lockfile), and each package
has the checks that prove it still works, in the engine's existing `[[checks]]`
format. The subsovereign backend entry is the real, tested one:

```toml
[[mirror]]                         # private git dependency, fetched by the host
name = "streamly-security-core"
url  = "https://github.com/MIIMAGINELabs/streamly-security-core"

[[repo]]
name = "subsovereign"
url  = "https://github.com/StreamlyApps/subsovereign"

  [[repo.package]]
  path      = "backend"
  ecosystem = "npm"
  image     = "node:20-bookworm"   # what the repo ships and its CI pins
  install   = ["npm ci --no-audit --no-fund"]
  mirrors   = ["streamly-security-core"]
  check_network = "isolated"
  not_covered = ["Real mail delivery: platform-relay.test.ts uses an in-process SMTP sink ..."]
  env = { NODE_ENV = "test", JWT_SECRET = "ci-jwt-secret-...", API_KEY_SALT = "...",
          ENCRYPTION_KEY = "0123...", APPLE_BUNDLE_ID = "test.bundle", DATABASE_URL = "...", ... }

    [[repo.package.sidecars]]
    name = "postgres"   image = "postgres:16"   health = "pg_isready -U postgres"
    [[repo.package.sidecars]]
    name = "redis"      image = "redis:7"       health = "redis-cli ping"

    # typecheck · openapi-reproducible · fixture-ids · unit-tests (JUnit) · audit-chain (JUnit)

  [[repo.package]]
  path        = "sdk-ios"
  ecosystem   = "swift"
  unsupported = "needs a macOS runner (swift test / xcodebuild)"
```

The whole repository is deployed, not just the package, because suites read
files elsewhere in the repo (subsovereign's backend reads `docs/guides` and the
SDKs). Checks start in the package directory.

`estate validate` checks the manifest and **refuses values that look like real
credentials** (GitHub, AWS, Slack, Stripe, npm tokens, private keys): every
value in it reaches a sandbox. Host-specific settings come from the environment
(`PATCHLAB_INTERNAL_ESTATE_WORKDIR`, `PATCHLAB_INTERNAL_CA_BUNDLE`), so one
committed manifest works on every runner.

### 3.2 Engine changes (built)

General features; nothing estate-specific is in the engine. All are usable
from a plain config too ([examples/services](../examples/services/patchlab.toml)).

| Change | Why |
|---|---|
| **`[sandbox].install`**: runs after deploy, again after the patch, again after the rollback. A failure before the patch is ERROR; after the patch it's a FAIL finding (the change broke the install). | A dependency bump was otherwise tested against the old `node_modules`: `setup` runs once, cached, before deploy. (Review item 1.) |
| **`[[sidecars]]`**: service containers on a per-run `--internal` network, reachable by name, health-checked before deploy, removed with the sandbox; `gc` and the final sweep remove them and the network too. | Postgres, Redis. |
| **`[[mirrors]]`**: host bare repositories copied into the sandbox, with git `insteadOf` rules passed as `GIT_CONFIG_*` environment (git 2.31+). The lockfile is unchanged; npm resolves `git+ssh://git@github.com/...` to the mirror. | Private dependencies without a token in the sandbox. (Review item 2.) |
| **`check_network = "isolated"`**: the sandbox leaves the outside network after each install and rejoins only for the next one. Checks reach the sidecars and nothing else. | A test can't phone home, fetch, or depend on the internet. |
| **`[sandbox].ca_bundle`**: a CA bundle trusted by every common tool (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, ...). | Runners behind TLS-inspecting proxies. |
| **`[sandbox].workdir`**: where install commands and checks start. | Packages in subdirectories. |
| **`run --no-patch`**: baseline only; failures reported as they are. | Health runs. |
| **Tests that stop running**: a test that passed before and is skipped after is a finding; so is one that stops being reported. The rollback comparison is per test too. | A skipped test proves nothing. |
| **Report metadata**: repository, branch, commit, package, image. | Reports and PRs say exactly what was tested. |

### 3.3 State

Plain JSON under `<workdir>/state/`, written atomically:

```
state/<package>/scan.json                     latest advisories and possible proposals
state/<package>/health/<run>/summary.json     health result + the engine report
state/<package>/proposals/<dep>/<run>/        change.patch, proposal.json, decision.json,
                                              pr.md, runs/<run>/report.{html,md,json}
state/digest/<date>.md                        the daily digest
```

The digest (and the M5 Estate page) read only these files. One estate command
runs at a time (a lock file in `state/`).

## 4. The lifecycle

### 4.1 Dependency and security updates

#### 4.1.1 Scan

Per package, in a tool container of the package's image: `npm audit
--package-lock-only --json`, and again with `--omit=dev` to mark production
advisories. `--package-lock-only` means nothing is installed or executed. An
audit that fails is an error, never a clean result.

Advisories are grouped into proposals:

- **major**: one per direct dependency whose fix is a semver-major upgrade
  (nodemailer 6 → 9, vitest 3 → 4). Labelled `breaking-risk`.
- **in-range**: every fix within declared ranges, together (`npm audit fix`
  without `--force`): express/body-parser/qs and friends.
- **manual**: no fix published, or the fix is a major upgrade of a package that
  isn't a direct dependency. Reported with the reason.
- **ignored**: listed in `[ignore]` in the manifest with a reason.

Python, Go and Cargo packages are scanned with their own ecosystem's tool, in
a tool container, and reported but not yet proposed (`estate/advisories.py`):

- **Python**: the package's install commands run, `pip freeze` records exactly
  what was installed (transitive dependencies included), and `pip-audit
  --no-deps --disable-pip` audits that list from its own virtualenv, so neither
  it nor its dependencies are in the result.
- **Go**: `govulncheck -format json`, counting only advisories whose vulnerable
  code the module calls, as latticeiq's CI does.
- **Cargo**: `cargo audit --json` against `Cargo.lock`. Unmaintained, unsound
  and yanked crates are listed at severity "info".

The tools are pinned. None of them reports a severity for every advisory, so
these show severity "unknown" rather than a guess, and the digest marks their
production share as unknown. Packages with no scanner (`swift`, `sql`) show
"not scanned", never "clean".

#### 4.1.2 Propose

In a tool container with the outside network (for the registry) and no
credentials (private dependencies come from the mirrors):

1. **Choose the version.** Using npm's own `semver`, list the published stable
   versions above the installed one, drop every version any of the
   dependency's advisory ranges covers, and take the newest release in the
   lowest remaining major. npm's own suggestion is the fallback.
2. **Change only the manifest and lockfile**: `npm install --package-lock-only
   --ignore-scripts <dep>@<version>` (or `npm audit fix --package-lock-only`).
   No dependency code runs while building a proposal.
3. **Re-audit** the new lockfile. If the dependency still has advisories, try
   the next candidate.
4. **Keep the diff minimal.** npm re-serialises `package.json` (it turned
   subsovereign's `—` escape into a literal dash), so only the changed
   dependency specs are edited into the original text. Adding or removing a
   dependency is refused.
5. **Capture** `git diff` as the change, and analyse the lockfile change:
   packages upgraded, added, removed; new install scripts; packages resolved
   from anywhere but the npm registry or a declared mirror; missing integrity
   hashes.

#### 4.1.3 Test

One engine run on a fresh checkout: install → baseline checks → apply the diff
→ **install again** → the same checks → compare per test → reverse the diff →
**install again** → the checks a third time. If anything regressed, the whole
run is repeated once: failures present in both runs are real, the rest flaky.

#### 4.1.4 Triage: the gate

| Gate item | Red means |
|---|---|
| tested | the run didn't complete (INCONCLUSIVE) |
| no regressions | a check or test that passed before fails after, or the change broke the install (BLOCKED) |
| no tests lost | a check didn't run, a test was skipped or vanished, or results couldn't be parsed (BLOCKED) |
| rollback verified | reverting the change didn't restore every passing check and test (BLOCKED) |
| advisories fixed | a targeted advisory is still reported, or the re-audit didn't run (BLOCKED) |
| no new advisories | the change brings in a new advisory (BLOCKED) |
| change scope | the proposer touched anything but the manifest and lockfile (BLOCKED) |
| supply chain | new install script, non-registry source, missing integrity (REVIEW) |
| new packages | a package not previously in the tree (REVIEW) |
| platform coverage | the package is marked unsupported (REVIEW) |

**READY** and **REVIEW** can become draft PRs; **BLOCKED** and
**INCONCLUSIVE** go to the digest with what broke. Pre-existing failures never
block, and are always listed.

#### 4.1.5 Publish

Today (`publish = "report-only"`): `pr.md` (the PR body: advisories, diff
summary, lockfile table, gate, notes, what isn't covered, how it was tested)
next to the patch and the full report. From M4, READY/REVIEW proposals become
draft PRs on `patchlab-internal/<package>/<dep>`; one open PR per package and
dependency, updated in place when a newer fix appears. It never touches
branches it didn't create.

### 4.2 Build health

`estate health` runs every package's checks on the head of its branch with no
change (`--no-patch`) and compares with the previous health run:

- **broken**: tests that passed last time and fail now, re-run once to rule
  out flakiness, with the commits in between;
- **flaky**: failed once, passed on the re-run;
- **failing**: failures that aren't new (listed, not re-alarmed);
- **not verified**: `unsupported` packages, every day.

This is what catches the survey's two blind spots: sentry has no CI, and
subsovereign's CI hasn't run since 8 September.

### 4.3 Consistency and drift (M5)

Rules as data, evaluated on each checkout, report-only at first:

| Rule | Example today |
|---|---|
| Runtime is supported (Node, Python, Alpine, Go, Rust edition against a dated end-of-life table) | Node 20 in subsovereign, caer, sentinel |
| Every package has a committed lockfile | sentinel's dashboard |
| Dependency audit runs on a schedule, not only when a path changes | sentinel's `pip-audit` |
| LICENSE file present and matches the manifest's declared licence | sentry declares Apache-2.0, no file |
| SDK and its sample use the same toolchain versions | subsovereign Android: Kotlin 2.0.21 vs 2.2.0 |
| No stray empty or oversized files at the root | subsovereign's `invalid` |
| CI has run on the default branch in the last N days | subsovereign |

A drift fix that changes what ships (a runtime bump such as Node 20 → 24) is a
proposal tested like any other, on its own, never folded into a dependency bump.

### 4.4 Digest and Estate page

`estate digest` writes `state/digest/<date>.md`: first what needs a person
(broken health, READY/REVIEW proposals), then one row per package (health,
advisories, proposals), then the details. M5 renders the same data as an
Estate page in the existing web front end, with the same localhost-and-token
security model.

### 4.5 Assisted fixes (M6)

When a major upgrade is BLOCKED because the code needs to change (a renamed
API, a stricter type), triage already knows which tests broke and how. M6 turns
that into a fix brief (failing tests, errors, the upgrade's changelog) for a
coding agent, whose patch then goes through **the same gate** as any other
change, with the dependency bump. The agent never gets credentials and never
publishes; the gate and a person decide.

## 5. Security

### 5.1 Access

- **GitHub:** read on all six repos; from M4, write only to create branches
  prefixed `patchlab-internal/` and open draft PRs. A GitHub App installed on
  MIIMAGINELabs and StreamlyApps is preferred to a personal token: it's scoped
  to these repos and its actions are attributed.
- **Never:** push to a default branch, force-push, merge, approve, or edit a
  branch it didn't create.

### 5.2 Private dependencies without secrets in sandboxes

subsovereign's backend depends on `@streamly/security-core`, a private repo in
another organisation. Its CI needs a `CADARN_REPO_TOKEN` secret just to run
`npm ci`. PatchLab Internal doesn't pass that token into a sandbox. Instead:

1. The **host** keeps a bare mirror of the private repo (`estate sync`), using
   its own read credentials, the same ones it uses to fetch the six repos.
2. The mirror is **copied** into the sandbox (not mounted), and git is told,
   via environment, to read `git+ssh://git@github.com/MIIMAGINELabs/streamly-security-core.git`
   from that copy.
3. The lockfile's pinned commit is checked out from the mirror as usual; the
   lockfile itself doesn't change.

Verified on 2026-09-28: `npm ci` for subsovereign's backend installs
`@streamly/security-core` 1.4.0 at the pinned commit this way, with no token
anywhere in the sandbox or its environment.

### 5.3 Sandboxes

- One container per run, `no-new-privileges`, memory/CPU/PID limits, labelled
  for exact clean-up.
- **Network:** the outside network only while installing; checks run on the
  per-run internal network with just the sidecars. Sidecars never have an
  outside route.
- **Code execution:** dependency install scripts run only inside test
  sandboxes. Scans and proposals use `--package-lock-only --ignore-scripts`, so
  building a proposal never runs dependency code.
- **Secrets:** none. Test values in `estate.toml` are throwaway; `estate
  validate` rejects anything shaped like a real credential.
- **Supply chain:** installs use the lockfile (`npm ci`); new install scripts,
  non-registry sources, missing integrity hashes and brand-new packages make a
  change REVIEW, never READY.

## 6. Where it runs

A Linux host with Docker, reachable to GitHub and the package registries,
running `estate cycle` from a systemd timer
([deploy/systemd](../deploy/systemd)): sync, health for every package, scan and
propose-and-test for every fixable advisory, digest. The engine treats SIGTERM
as a cancel and tears everything down, so a timeout never leaves containers
behind. A self-hosted machine is preferable to GitHub-hosted Actions because
sidecars and many sequential sandbox runs are cheaper and faster there. It
also doesn't depend on subsovereign's Actions, where no job has reached a runner
since 8 September (cause unconfirmed; see §8).

Rough load: 6 repos, about 15 packages. subsovereign's backend takes about
five minutes per proposal (three passes of a 1,337-test suite) and under two
minutes per health run on 4 CPUs. A 4-CPU / 16 GB host covers the daily cycle.

## 7. Milestones

### M1: subsovereign nodemailer, end to end — done 2026-09-28

Built: the engine changes in §3.2, the estate layer (manifest, sync, scan,
propose, test, triage, health, digest, cycle), `estate.toml` for
subsovereign/backend, report-only publishing.

Evidence (run in a cloud container with Docker, subsovereign at `d3367e6`):

- `estate scan subsovereign/backend`: 10 vulnerable packages; proposals for
  nodemailer (major, production), in-range fixes (production) and vitest
  (major, dev only).
- `estate propose subsovereign/backend nodemailer` chose **nodemailer 9.1.1**
  (the lowest major with no known advisory; npm's own suggestion was 10.0.12),
  with a minimal diff: the spec line in `package.json`, and the spec plus the
  version, URL and hash of the one lockfile entry.
- The test ran typecheck, the OpenAPI reproducibility check, the fixture-id
  check, the unit suite and the audit-chain suite with Postgres 16 and Redis 7
  sidecars, before, after and after rollback: **1,332 passed, 2 failed, 3
  skipped in all three phases**; the same 2 tests fail on `main` without the
  change (see below). Rollback verified; all 12 nodemailer advisories gone in
  the re-audit; nothing new introduced. Verdict **READY**.
- `estate health` on the same commit: status "failing" (the same 2 tests,
  none new), and the digest lists the READY proposal under "needs a person".
- Nothing was left running afterwards (no containers or networks with the
  PatchLab Internal label).

Found on the way: two backend tests fail on a clean Linux checkout of `main`,
consistently (`gdpr-retention.test.ts` "keeps a reversed refund for tax" and
`subscriber-token-routes.test.ts` "the preflight allows X-Subscriber-Token").
Nobody would have seen this, because subsovereign's CI isn't running. The
second one's comment says its origin is in `ALLOWED_ORIGINS` "for the test
env", which neither the CI workflow nor this manifest sets, so it probably
depends on a developer's `.env` (inferred, not confirmed).

### M2: security updates for all six repos, report-only — done 2026-09-28

Built: `estate.toml` entries for all six repos (11 packages), each package's
checks copied from that repo's own CI (sentry has none, so the commands its
BUILD.md reports); Python, Go and Cargo scanners (§4.1.1); partial in-range
fixes (below); `sync` that carries on past an unreachable repo.

Evidence (cloud container with Docker, at the commits in the digest):

| Package | Health | Advisories | Outcome |
|---|---|---|---|
| subsovereign/backend | failing (the 2 known tests, §M1) | 10 | nodemailer READY (M1) |
| subsovereign/sdk-ios | not verified (macOS) | not scanned | — |
| latticeiq/backend | healthy, 649 tests | 0 of 56 | — |
| latticeiq/scanner-agent | healthy (build, vet, test) | 0 (govulncheck) | — |
| latticeiq/frontend | healthy, 86 tests | 0 | — |
| streamly-security-core | healthy (Node 24 only) | 0 | — |
| caer/packages/orchestrator | healthy, 33 tests | 1 (undici) | in-range fix READY |
| caer/packages/admin-console | healthy (typecheck only) | 6 | in-range fix REVIEW: 8 fixed, 2 react-router advisories need a major |
| caer/packages/shared-schema | healthy (migrations from empty) | not scanned (SQL) | — |
| sentinel/apps/proxy | healthy, 37 tests | 1 of 38 (cryptography) | manual: fixed in 50.0.0 |
| sentry | healthy (workspace build and test) | 0 of 98 crates | — |

Found and fixed in the manifest on the way: sentry's default branch is
`master`; caer's data-migration tests must run from the repo root; two
latticeiq netguard tests resolve public names, so they are deselected (checks
have no DNS) and listed under `not_covered`.

**Partial in-range fixes.** `npm audit fix` exits non-zero when some
advisories need a breaking change, after fixing the rest. When the lockfile
changed, the proposal keeps what npm fixed, records the rest as deferred, and
the gate's "partial fix" item makes the verdict REVIEW, never READY. If nothing
targeted was fixed it is BLOCKED.

Still open for M2's "done when": the Python, Go and Cargo findings are
reported, not proposed; sentinel's cryptography upgrade is the only one today.

### M3: build health on a schedule

The runner host, `estate cycle` on a timer, a week of daily runs.

**Done when:** a week of daily health runs for all six repos, with sentry and
subsovereign covered despite having no working CI.

### M4: draft PRs

GitHub App, branch naming, one PR per package and dependency, the PR body from
`pr.md`, updating its own branches.

**Done when:** a READY proposal becomes a draft PR that a person can review and
merge with no local steps.

### M5: drift rules and the Estate page

`rules.toml` with the rules in §4.3, the Estate page, the digest on the page.

### M6: assisted fixes

Fix briefs for BLOCKED major upgrades, handed to a coding agent, gated the same
way (§4.5).

## 8. Decisions needed

1. **Runner host:** which always-on Linux machine runs the cycle (M3).
2. **GitHub access for M4:** a GitHub App on MIIMAGINELabs and StreamlyApps
   (recommended), or a fine-grained token.
3. **Where the digest goes:** a file only, or also email or a chat channel.
4. **subsovereign's Actions:** someone with StreamlyApps access needs to find
   out why no job has reached a runner since 8 September (billing, a spending
   limit or a setting; unconfirmed).
5. **nodemailer 9.1.1 or 10.0.12:** 9.1.1 is the smaller jump and is clean
   today; 10.x ships its own types (so `@types/nodemailer` could go) and is
   where fixes will land first. PatchLab Internal proposes 9.1.1 by policy.

## Appendix: review items

The review of the first version of this design
(`patchlab-internal-review/docs-review.md`, 2026-09-28) and how each item was
resolved:

| # | Item | Resolution |
|---|---|---|
| 1 | Installs never re-run after patch or rollback | `[sandbox].install` (§3.2) |
| 2 | subsovereign needs a token for `@streamly/security-core` | Host-side mirrors; no token in sandboxes (§5.2) |
| 3 | Test environment incomplete | All five settings in `estate.toml`, same throwaway values as the repo's CI |
| 4 | Test on the runtime the repo ships | `node:20-bookworm`; a Node 24 move is its own proposal (§4.3) |
| 5 | `vitest` directly skips `pretest` | Explicit `fixture-ids` check |
| 6 | Survey §3 for subsovereign; OpenAPI check missing | Survey corrected; `openapi-reproducible` check added |
| 7 | `accelerate` example out of scope | Removed |
| 8 | Cause of subsovereign's stalled Actions unconfirmed | Stated as unconfirmed (§6, §8) |
| 9 | `@types/nodemailer` ^8 vs `nodemailer` ^6 | The typecheck passes on nodemailer 9.1.1 with `@types/nodemailer` ^8 unchanged; when a chosen version ships its own types, the proposal says the `@types` package can go (separately) |
