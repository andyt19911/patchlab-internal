# PatchLab Internal: estate control plane

Status: M1, M2 and M6 built and run end to end on 2026-09-28 (M6 covers container images, code scanning, committed secrets and CI workflows); M3 (nightly on GitHub Actions) and M4 (draft PRs, off) built; M5 proposed.
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

**Python, Go and Cargo** (`estate/fixers.py`) get one "upgrade" proposal per
vulnerable dependency, to the lowest version that fixes every advisory:

- **Python**: the exact pin in the package's requirement files moves to that
  version (a transitive dependency pinned nowhere gets a `name>=x` floor in
  `requirements.txt`). Unlike npm, proving the change means installing it, and
  pip may run a source package's build code: that happens in the tool
  container, which has no credentials.
- **Go**: `go get module@version && go mod tidy`.
- **Cargo**: `cargo update --package crate` (Cargo.lock only). When the newest
  compatible version is still vulnerable, the proposal says the fix needs a new
  major in `Cargo.toml`.

The re-audit decides whether the advisories are gone, and the change to the
installed set (upgraded, added, removed, non-registry sources) goes through the
same supply-chain items as npm's lockfile diff. A jump across a major version
is labelled `breaking-risk`.

**What a partial fix leaves.** When `npm audit fix` fixes what it can in range
and exits non-zero, the re-audit names the major upgrade the rest needs (caer's
react-router 6 → 7). That becomes a proposal of its own, tested separately. A
candidate counts as clean only when every package the plan covers is clean,
not just the one bumped.

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

#### 4.1.5 Publish (M4, built; off)

`publish = "report-only"` (today) writes `pr.md` next to each patch and
report. `estate publish` lists what it would open; `--apply` (and the cycle,
once `publish = "draft-pr"`) does it:

- Only READY and REVIEW decisions with a non-empty patch, tested on the
  branch's **current** head. A stale one waits for the next cycle's re-test.
- One branch per change, `patchlab/<package>/<key>`: one commit on the tested
  commit, authored by PatchLab Internal. A draft PR against the repo's branch,
  with `pr.md` as its body; REVIEW titles start `[needs review]`.
- A branch PatchLab didn't write every commit of is left alone and reported.
  An unchanged patch is not re-pushed (`state/published.json`).
- At most 5 new PRs a run (`--max-prs`). It never merges, approves or marks a
  PR ready for review.
- Tokens: `PATCHLAB_INTERNAL_GITHUB_TOKEN_<OWNER>` (a fine-grained token covers
  one owner) or `PATCHLAB_INTERNAL_GITHUB_TOKEN`, passed to git as an HTTP
  header through `GIT_CONFIG_*` environment variables: never on a command
  line, in a URL, or in a sandbox. The same tokens let `sync` read private repos.

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

### 4.5 Repair: failing tests (M6, built)

`estate repair <package>` (and `cycle`, when `[repair]` is configured) hands
the tests that fail in the latest health run to a coding agent:

1. A **brief** is written from the health run: each failing test, the lines of
   its log around the failure, the command that runs it, the environment and
   services the checks use, and the rules (fix the cause; never skip, weaken or
   delete a test; change as little as possible; follow the repo's CLAUDE.md).
2. The **agent** runs in its own tool container with a copy of the checkout.
   The credentials it needs are *named* in `[repair] env` and passed from the
   runner's environment with `docker run -e NAME` (the value is never on a
   command line or in `estate.toml`). They never reach a test sandbox.
3. Its edits (committed or not) are captured as a diff and **tested like any
   change**: baseline, apply, verify, roll back, verify, with the package's
   services, and a second run to separate flaky failures.
4. The **gate**: every targeted test must go from failing to passing; nothing
   else may regress or disappear; the rollback must bring the failure back. An
   edit to a test file or test configuration, or to a dependency manifest,
   makes it REVIEW: those are the changes that could make a test pass without
   fixing anything.

The cycle tries each (commit, set of failures) once, so a failure it couldn't
fix doesn't cost an agent run every night.

**Browser smoke check.** A package whose only check is a typecheck gets a
runtime check from PatchLab itself: `assets/browser_smoke.mjs` loads each route
in a headless Chromium sidecar and reports, per route, "renders" and "has no
uncaught errors" as TAP. It has no dependencies (DevTools protocol over a
minimal WebSocket client), so nothing is installed into the app under test.
caer's admin console uses it.

### 4.6 Container images (built)

`estate images [--propose]` reads every Dockerfile listed as `[[repo.image]]`.

- **Scan.** Each `FROM` (every stage, not earlier stages or `${ARG}` names) is
  pulled and scanned with Trivy for OS and bundled language packages. Trivy
  runs in its own container on a `docker save` of the image, never with the
  Docker socket.
- **Support.** The runtime line in the tag (node 20, python 3.11, alpine 3.20)
  is checked against its end-of-life date: endoflife.date when the runner can
  reach it, else a dated table in `images.py`. A line past (or within 90 days
  of) its end gets a move to the lowest supported line with at least a year
  left; odd Node majors are never proposed.
- **The move** changes the Dockerfile's `FROM` lines, the `node-version` /
  `python-version` pins in the CI jobs that build that package (jobs that name
  its directory; a version matrix is left alone), and `.nvmrc`-style files.
- **Test.** The linked package's full checks run on today's sandbox image and
  on the same image moved to the new line; nothing that passes today may fail.
  Both Dockerfiles are built, and the new base is re-scanned.
- **Gate.** BLOCKED if a test that passes today fails, the image built before
  and not after, the new base has more fixable high or critical
  vulnerabilities, or anything but runtime pins changed. REVIEW when a check
  could not be made (no package's checks exercise the image, or it doesn't
  build on this runner either way). A failed scan is INCONCLUSIVE, never a pass.

### 4.7 Code scanning and committed secrets (built)

`estate code-scan` scans each package's own code; `estate code-fix` (and the
cycle, with `[repair]`) fixes what it finds.

| Tool | What | How it runs |
|---|---|---|
| Opengrep 1.4.2 | the rules `[sast] rules` names: Caer's own clean-room rulesets (injection sinks, unsafe deserialisation, quantum-vulnerable crypto) | own image, binary checked against Caer's pinned sha256; `--network none`, read-only |
| gitleaks 8.30.1 | credentials committed to the code; values redacted by gitleaks itself | own static image built through the Go checksum database; `--network none`, read-only |
| bandit 1.9.4 | Python | tool container |
| gosec 2.29.0 | Go | tool container |
| workflow checks | script injection and `pull_request_target` checkouts in CI (§4.8) | in process |

A finding is identified by tool, rule, file and the flagged line's text, so it
survives code moving around it. High findings outside test code become one fix
plan per rule and file. The repair agent gets the locations and the rules (fix
the cause; no suppression comments; if it is sure it is a false positive, change
nothing and say why, and a person decides). Its change is tested like any other,
then the code is **re-scanned**: the gate needs the finding gone, no new high or
medium finding, no suppression comment added, no regression, rollback verified.
An incomplete re-scan is INCONCLUSIVE. For a committed secret, the fix moves it
to configuration and the decision says the credential must still be rotated:
deleting it from the code does not revoke it, and it stays in history.

### 4.8 CI workflows (built)

`estate actions [--propose]` scans `.github/workflows` for actions used by a
movable tag, script injection, `pull_request_target` checkouts of PR code and
workflows with no `permissions:` block. Pinning is deterministic: each tag is
resolved with `git ls-remote` against the action's repository and the line
becomes `uses: owner/repo@<sha> # v4`. The gate checks every pin resolved, a
re-scan finds nothing unpinned, and only `uses:` lines changed; CI then runs
exactly the code it runs today, so it is READY without a CI run. Script
injection goes to the repair agent through §4.7.

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

Closed after M2 (see M6): Python, Go and Cargo findings are now proposed and
tested, not just reported.

### M3: build health on a schedule — built 2026-09-28

`.github/workflows/estate-nightly.yml` runs `estate cycle` at 02:00 UTC on a
GitHub-hosted runner (Andy's choice, 2026-09-28), and on demand. State
carries over in the Actions cache; the digest is the run summary and an
artifact with every decision, PR body and patch. It needs one read-only token
per owner as repository secrets (the workflow's header lists them) and runs
only from the default branch, so it starts once this branch is merged.

### M4: draft PRs — built 2026-09-28, off

§4.1.5. A dry run at the M2/M6 commits lists 13 draft PRs across four repos
(7 READY, 6 REVIEW). Turning it on is Andy's call: `publish = "draft-pr"` in
estate.toml plus write access on the tokens.

### M5: drift rules and the Estate page

`rules.toml` with the rules in §4.3, the Estate page, the digest on the page.

### M6: PatchLab fixes everything it finds — built 2026-09-28

Andy's rule: nothing is fixed by hand; every gap is a PatchLab capability.
Built: Python/Go/Cargo proposals (§4.1.2), follow-up majors for partial npm
fixes, the browser smoke check, and repair of failing tests by a coding agent
(§4.5). Evidence, at the same commits as M2:

| Case | What PatchLab did | Verdict |
|---|---|---|
| sentinel `cryptography` 49.0.0 (PYSEC-2026-3552) | pinned 50.0.0 in requirements.txt; 37 tests before, after, rollback | READY (`breaking-risk`) |
| caer admin-console, 8 in-range advisories | lockfile fix; typecheck, build and 10 browser-smoke tests | REVIEW (2 left for a major) |
| caer admin-console, react-router 6 → 7 | found from the partial fix; 7.18.4; smoke 10/10 after | REVIEW (adds `cookie`, `set-cookie-parser`) |
| subsovereign CORS preflight test | repair brief, scripted stand-in agent, full suite | REVIEW (the fix edits a test file) |

Images, code and CI, run on 2026-09-28 at the same commits:

| Case | What PatchLab did | Verdict |
|---|---|---|
| 8 Dockerfiles scanned | 6 on end-of-life runtimes (node 20 ×5, alpine 3.20) | — |
| subsovereign backend, node 20 → 24 | full suite on node:20 and node:24: 1,338 passing on both, the same 2 pre-existing failures; fixable high/critical in the base 24 → 4 | REVIEW (the image doesn't build on this runner either way) |
| caer jscpd and opengrep images, sentinel dashboard | moved and re-scanned; no package's checks exercise them | REVIEW |
| code scan, 11 packages | complete for every package; 4 blocking findings: gosec G115 on a line that is itself a bounds check, G402 `InsecureSkipVerify` in the TLS probe (deliberate: a scanner must reach hosts with bad certificates), a placeholder `ENCRYPTION_KEY` in `.env.example`, and `new Function('s', 'return import(s)')` for an ESM import | all four read as false positives; the agent's false-positive path puts each to a person |
| CI workflows, 5 repos | 41 actions pinned to their tags' commits in 4 repos (streamly-security-core already pins) | READY ×4 |

The repair run used a **scripted stand-in** for the agent, because the runner
has no agent credential yet: it proves the brief, the capture, the full-suite
test and the gate, not an agent's judgement. The gate would BLOCK a change
that leaves a targeted test failing (unit-tested). With `[repair]` configured,
the GDPR retention test (a real product bug: an erasure deletes a refund's
reversal) goes through the same path.

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
6. **Repair agent credential:** `[repair]` needs an agent API key on the runner
   (named in `env`, never in the file). Until then repair is off.

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
