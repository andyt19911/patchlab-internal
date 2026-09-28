# Estate survey

A read-only survey of the six repositories PatchLab Internal maintains first:

| Repo | Organisation | What it is |
|---|---|---|
| latticeiq | MIIMAGINELabs | Quantum-readiness platform: discovers IT assets and assesses them against post-quantum cryptography requirements |
| streamly-security-core | MIIMAGINELabs | `@streamly/security-core`, a post-quantum crypto toolkit (FIPS 203/204) used by the other products |
| caer | MIIMAGINELabs | Sentinel Caer, a self-hosted code quality and security scanning platform |
| sentinel | MIIMAGINELabs | Sentinel, a self-hosted AI security gateway (proxy + dashboard) |
| sentry | MIIMAGINELabs | Merlyn Sentry, a Rust gateway: auth (OAuth PKCE, dynamic client registration), secret injection, registry with RBAC, audit |
| subsovereign | StreamlyApps | Self-hosted subscription platform (an Adapty alternative): backend, dashboard, CLI and SDKs for Web, React, React Native, Fire TV, iOS/tvOS, Android, Flutter and Roku |

Taken on 2026-09-28 from shallow clones of each default branch. Nothing was
changed in any surveyed repository.

---

## 1. Headline findings

| # | Finding | Repos |
|---|---|---|
| 1 | **Known-vulnerable dependencies in 3 of 6 repos**, including a production one: subsovereign's backend uses **nodemailer 6.x, which can send email to an unintended domain**. The fix (10.0.12) is a major-version bump. subsovereign's `sdk-vega` ships 7 high-severity advisories to anyone who installs it. caer's admin console has 3 high, and sentinel's proxy has a `cryptography` advisory. | subsovereign, caer, sentinel |
| 2 | **Only 3 of 6 repos are really tested on every change.** latticeiq, caer and streamly-security-core are green on main. **subsovereign's CI hasn't run since 8 September**: its last 8 runs failed before a runner was assigned. sentinel only runs `pip-audit`, and only when its requirements file changes (last run 5 July). sentry has no CI at all: its `BUILD.md` says 43/43 tests pass, but nothing re-runs them. | subsovereign, sentinel, sentry |
| 3 | **No repo has Dependabot or Renovate.** latticeiq has GitHub dependency review on PRs and runs `govulncheck` in CI; nothing proposes updates anywhere. | all 6 |
| 4 | **Node 20 is end-of-life** (April 2026) but is still used by subsovereign (CI and all 3 Dockerfiles), caer (CI and Docker, plus `alpine:3.20`, also end-of-life) and sentinel's dashboard image. streamly-security-core still declares and tests Node 20 support. sentinel's proxy runs on Python 3.11. | subsovereign, caer, sentinel, streamly-security-core |
| 5 | **Missing basics.** No LICENSE file in 5 of 6 repos (only streamly-security-core has one; sentry declares Apache-2.0 in `Cargo.toml` but has no file). sentry has no README. sentinel's dashboard has no npm lockfile, so its builds aren't reproducible and it can't be audited. | all but streamly-security-core |
| 6 | **Drift inside subsovereign.** The Android sample builds with Kotlin 2.2.0 and `compileSdk` 36, while the SDK it's meant to test ships with Kotlin 2.0.21 and `compileSdk` 35. An empty file named `invalid` was committed to the repo root today, apparently by accident. | subsovereign |

What's in good shape: **latticeiq** and **streamly-security-core** are active,
green on main and have no known vulnerable dependencies. latticeiq's backend
installs from a fully pinned `requirements-lock.txt`, and its CI checks
migrations up and down and runs `govulncheck` on the Go agent.

---

## 2. The six repos at a glance

| Repo | Stack | Last commit | CI on main | Test files | Lockfiles | Runtime |
|---|---|---|---|---|---|---|
| latticeiq | Python, TypeScript, Go | 2026-09-26 | ✅ ci, dependency-review | 51 | npm, pip lock, go.sum | python:3.14-slim, golang:1.27; Node 24 in CI |
| streamly-security-core | JS/TS (npm package) | 2026-09-26 | ✅ ci (Node 20/22/24 matrix) | 2 | npm | Node ≥ 20.19 |
| caer | TypeScript (2 packages), SQL | 2026-09-22 | ✅ ci, rules | 11 | npm per package | node:20-alpine, alpine:3.20; Node 20 in CI |
| subsovereign | TypeScript, Swift, Kotlin | 2026-09-28 | ❌ not running since 2026-09-08 | 145 | 9 npm, Gradle wrapper | node:20-alpine, node:20-bookworm-slim; Java 17; Swift 5.9 |
| sentinel | Python, JS | 2026-07-06 | ⚠️ pip-audit only, path-triggered | 5 | pinned `requirements.txt`; **no npm lock** | python:3.11-slim, node:20-slim |
| sentry | Rust (5-crate workspace) | 2026-07-23 | — none | 6 | Cargo.lock | Rust 2021, bundled SQLite |

---

## 3. How each one builds and tests

These are the commands PatchLab Internal's checks would run, taken from each
repo's CI or manifests. None has been run for this survey.

| Repo | Build and test |
|---|---|
| latticeiq | backend: `pip install -r requirements-lock.txt`, `alembic upgrade head` / `downgrade base` / `check`, `pytest tests/` (needs Postgres; CI uses 18); frontend: `npm ci`, `npm run typecheck`, `npm test`, `npm run build`; scanner-agent: `go build`, `go vet`, `go test`, `govulncheck` |
| streamly-security-core | `npm ci`, `npm test`, `npm run test:enterprise` |
| caer | per package (`orchestrator`, `admin-console`): `npm ci`, `npm run typecheck`, `npm test`, `npm run build`; plus the `rules` workflow |
| subsovereign | backend: `npm ci`, `npm run lint`, `npm run migrate`, `npm test` (needs Postgres 13+ and Redis); dashboard and each JS SDK: `npm ci`, `npm test` / `npm run build`; Android: `./gradlew testDebugUnitTest`; iOS: `swift build`, `swift test`, `xcodebuild test` (**macOS only**) |
| sentinel | proxy: `pip install -r apps/proxy/requirements.txt`, `pytest apps/proxy/tests`; dashboard: `npm install`, `npm run build` (no lockfile) |
| sentry | `cargo build --workspace`, `cargo test --workspace`; release: `cargo build --release -p sentry-gateway` |

---

## 4. Security audit results

Run on 2026-09-28 with `npm audit --package-lock-only`, `pip-audit` and
`cargo audit`. "Production" excludes devDependencies.

| Repo / package | Result | Fix |
|---|---|---|
| **subsovereign/backend** | 5 high, 5 moderate in total; **production: 1 high, 3 moderate**: nodemailer (email to an unintended domain), express, body-parser, qs | nodemailer 6.x → 10.0.12 (**major**); the rest are in-range updates |
| **subsovereign/sdk-vega** | 7 high, 3 moderate, 1 low, all in dependencies that ship with the SDK: `ip` (SSRF), `image-size`, `js-yaml`, `@react-native-community/cli*`, `react-native` | Available for all; they come through the React Native toolchain |
| subsovereign/sdk-react-native | 2 high, 8 moderate, **dev tooling only** | Available |
| subsovereign/sdk-react-native-sample | 10 moderate (sample app) | Available |
| subsovereign: cli, dashboard, sdk-js, sdk-react, sdk-web | clean | — |
| **caer/packages/admin-console** | 3 high (browserslist, nanoid, postcss), 3 moderate (react-router, react-router-dom, baseline-browser-mapping) | Available |
| caer/packages/orchestrator | 1 moderate (undici) | Available |
| **sentinel/apps/proxy** | cryptography 49.0.0, PYSEC-2026-3552 | cryptography ≥ 50.0.0 |
| sentinel/apps/dashboard | **not auditable**: no lockfile | Commit a lockfile |
| latticeiq backend (lock), frontend | clean | — |
| latticeiq scanner-agent (Go) | not re-audited here (`vuln.go.dev` is blocked from this environment); its own CI runs `govulncheck` and was green on 2026-09-26 | — |
| streamly-security-core | clean | — |
| sentry | clean (98 crates) | — |

---

## 5. subsovereign in detail

subsovereign is the largest repo in scope (850 files, 145 test files) and
the hardest to maintain: 9 npm lockfiles, a Gradle build, a Swift package,
and CI that needs a macOS runner.

**Its CI isn't actually running.** The last 8 runs on `main` (7 and 8
September) failed within 3 to 9 seconds, with no steps, no runner and no
logs, so no test ran. No run has been recorded since 8 September, although
`main` has had commits since then (the latest today). That pattern usually
means GitHub Actions is blocked at the account level (a billing or spending
limit) or disabled for the repository. Someone with access to the
StreamlyApps settings needs to check. Until then, nothing is testing
subsovereign's changes.

---

## 6. What this means for PatchLab Internal

1. **Dependency and security updates.** Start with subsovereign's backend
   nodemailer 6 → 10 upgrade. It's a production security fix, it's a major
   version with possible breaking changes, and the backend has a real test
   suite, so it's exactly what before/after testing in a sandbox is for.
   Next: sentinel's `cryptography` 50, then caer's admin-console bumps and
   sdk-vega's toolchain updates.
2. **Build health.** A nightly "does it build and pass its own tests" run
   matters most where nothing runs today: subsovereign (until its CI is
   fixed, and permanently for a second opinion), sentinel (whose tests never
   run in CI) and sentry (no CI at all).
3. **Consistency and drift.** Checks worth making on all six: LICENSE file,
   lockfile for every package, supported runtime (no Node 20, Alpine 3.20 or
   stale Python), a scheduled rather than path-triggered audit, and matching
   toolchains between an SDK and its sample.
4. **Estate dashboard.** §2 and §4 are a first, static version: one row
   per repo with CI state, runtime and advisories. The tool should
   regenerate it on a schedule.

Things the design needs to handle:
- **Four ecosystems:** npm (including per-package lockfiles in caer and 9
  in subsovereign), Python, Cargo and Go, plus Gradle.
- **Services:** latticeiq's backend tests need Postgres, and subsovereign's
  need Postgres and Redis, so sandboxes need those running alongside the
  code under test.
- **macOS-only builds:** subsovereign's iOS/tvOS SDK can't be built in a
  Linux sandbox. The report must say what wasn't verified rather than pass
  it silently.
- **Credentials:** tests must run with fixtures and dummy secrets (as
  latticeiq's CI already does), never real keys.

---

## 7. Method and limits

- Shallow clones (`--depth 1`) of each default branch as of 2026-09-28.
- Stack, lockfiles, Dockerfiles, CI and test-file counts come from the file
  tree; test counts measure presence, not whether the tests pass.
- No builds or test suites were run, apart from the dependency resolution
  that `cargo audit` needs.
- CI state comes from the latest GitHub Actions runs on each default branch.
- Audits show known advisories on the date above; new ones are published
  all the time, which is why the tool must re-run them on a schedule.
