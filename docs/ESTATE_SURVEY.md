# MIIMAGINELabs estate survey

A read-only survey of the MIIMAGINELabs and StreamlyApps repositories, taken on 2026-09-28 from
shallow clones of each default branch. It is the baseline PatchLab Internal is
being built to maintain: what each tool is, how it builds and tests, and where
it stands on dependencies, security fixes, build health and consistency.

Nothing was changed in any surveyed repository.

**Scope:** 26 MIIMAGINELabs repositories plus `StreamlyApps/subsovereign`, the
only StreamlyApps repository visible to this survey (§6).
`MIIMAGINELabs/PatchLab` (the public release repo) is left out. `claude-config` is a personal `~/.claude` backup rather than a
tool, so it is listed but not scored.

---

## 1. Headline findings

| # | Finding | Repos | Why it matters |
|---|---|---|---|
| 1 | **Known-vulnerable dependencies in 9 repos.** 10 npm lockfiles, 3 pinned Python files and 1 Cargo lockfile have advisories, almost all with fixes available (details in §4 and §6). | 9 | They are the first candidates for automated, tested updates. |
| 2 | **22 of 27 repos have no CI at all, and subsovereign's hasn't run since 8 September (§6).** Only latticeiq, caer and streamly-security-core run tests on push; sentinel runs `pip-audit` only when its requirements file changes. | 22 | Nothing tells anyone when these repos stop building. |
| 3 | **No repo, in either organisation, has Dependabot or Renovate.** latticeiq has GitHub dependency review on PRs; nothing proposes updates anywhere. | 26 | Advisories are only found when someone looks. |
| 4 | **Node 20 is end-of-life** (April 2026) but is still the Docker runtime in 6 repos and in the CI of caer and subsovereign, and `engines` fields in 3 repos still allow it. `alpine:3.20` (caer) is also past end of life. | 8 | Runtime security fixes stopped five months ago. |
| 5 | **Two Rust crates can't build as committed.** `sovereign-agent-queue` and `sovereign-agent-kafka` keep `lib.rs` at the repo root with no `[lib] path`, so Cargo finds no target. Both also depend on `../sovereign-agent` by path, so they only build when checked out next to it. | 2 | Build-health failures that no CI would currently catch. |
| 6 | **Unpinned or range-only dependencies** with no lockfile: merlyn-forge, llm-gateway (`>=` ranges), and 5 Rust crates without `Cargo.lock`. | 7 | Builds aren't reproducible, so a test today says little about the build tomorrow. |
| 7 | **Missing basics:** 25 repos have no LICENSE file, 8 have no README. `sovereign-mcp`'s `Cargo.toml` has no `edition`, so it silently builds as Rust 2015. | 25 / 8 / 1 | Consistency drift across the estate. |
| 8 | **A 54 MB model file is committed directly** (not Git LFS) in streamly-ai-router: `models/miimagine-v1/adapter_model.safetensors`. | 1 | Every clone and CI checkout pays for it; history grows with each retrain. |

What's in good shape: latticeiq, caer and streamly-security-core are active,
green on main, and latticeiq's backend has a fully pinned
`requirements-lock.txt` with no known vulnerabilities.

---

## 2. The estate at a glance

Stack = main languages by file count. CI = workflows on the default branch.
Tests = number of test files found (not whether they pass). Lock = a lockfile
is committed.

| Repo | What it is | Stack | Last commit | CI | Tests | Lock | Docker base |
|---|---|---|---|---|---|---|---|
| latticeiq | Quantum-readiness platform | Python, TS, Go | 2026-09-26 | ci, dependency-review ✅ | 51 | ✅ | python:3.14-slim, golang:1.27 |
| streamly-security-core | Post-quantum crypto toolkit (npm) | JS/TS | 2026-09-26 | ci ✅ | 2 | ✅ | — |
| caer | Code scanning platform (Sentinel suite) | TS | 2026-09-22 | ci, rules ✅ | 11 | ✅ (per package) | node:20-alpine, alpine:3.20 |
| streamly-ai-router | Merlyn AI router | JS | 2026-09-16 | — | 16 | ✅ | node:20-slim |
| rosetta | Spec → docs/SDK/CLI generator | Rust | 2026-09-10 | — | 8 | ✅ | — |
| sovereign-mcp | (no README) | Rust | 2026-08-15 | — | 7 | — | — |
| sovereign-agentic-network | Cross-product agent layer | TS, Terraform | 2026-08-07 | — | 3 | ✅ | node:20-slim ×5 |
| merlyn-forge | Fine-tuning platform | Python | 2026-07-23 | — | 1 | — | — |
| merlyn-ecoms-plane | Commerce control plane | Python | 2026-07-27 | — | 0 | pinned reqs | python:3.12-slim |
| merlyn-commerce | Self-hosted e-commerce | Python, SQL | 2026-07-27 | — | 18 | pinned reqs | python:3.12-slim |
| llm-gateway | OpenAI-compatible tracing proxy | Python | 2026-07-23 | — | 5 | — | python:3.12-slim |
| prism | Market-intelligence platform | JS | 2026-07-23 | — | 0 | — | node:20-alpine |
| deploy-api | Merlyn deploy platform | Rust | 2026-07-19 | — | 0 | ✅ | — |
| sovereign-agent | Zero-dep agent core (crate) | Rust | 2026-07-23 | — | 1 | ✅ | — |
| sovereign-agent-queue | In-process queue for sovereign-agent | Rust | 2026-07-23 | — | 0 | — | — |
| sovereign-agent-kafka | Kafka adapter for sovereign-agent | Rust | 2026-07-23 | — | 0 | — | — |
| sovereign-twin | Digital-twin extension | Rust | 2026-07-23 | — | 0 | — | — |
| artificer | Prompt → app engine | Rust | 2026-07-23 | — | 0 | — | — |
| sentry | (no README) | Rust | 2026-07-23 | — | 6 | ✅ | — |
| merlyn-memory | Long-term memory service | TS | 2026-07-13 | — | 0 | ✅ | — |
| sentinel | Self-hosted AI security gateway | Python, JS | 2026-07-06 | pip-audit (path-triggered) | 5 | pinned reqs | python:3.11-slim, node:20-slim |
| sigil | Animation format + engine | JS | 2026-07-05 | — | 1 | — | — |
| streamly-agent-platform | (no README) | JS | 2026-06-21 | — | 0 | ✅ | — |
| miimagine-docs | Platform documentation | HTML/Markdown | 2026-09-25 | — | — | — | — |
| cadarn-site | Static site | HTML/CSS | 2026-07-29 | — | — | — | — |
| **subsovereign** (StreamlyApps) | Subscription platform + 9 SDKs (§6) | TS, Swift, Kotlin | 2026-09-28 | backend, dashboard, sdks ⚠️ not running since 09-08 | 145 | ✅ (9) | node:20-alpine, node:20-bookworm-slim |
| claude-config | Personal `~/.claude` backup (not scored) | Shell | 2026-09-28 | — | — | — | — |

Stacks across the estate: **Rust 9 repos, JS/TS 10, Python 7**, plus Go in
latticeiq, Terraform in sovereign-agentic-network, and Swift and Kotlin in
subsovereign's mobile SDKs. Any maintenance tool has
to handle all three ecosystems from day one.

---

## 3. Build and test commands found

These are what PatchLab Internal's checks would run. They come from the
manifests; none has been run yet, apart from the audits in §4.

| Ecosystem | Repos | Build / test |
|---|---|---|
| npm | latticeiq/frontend, caer (2 packages), streamly-ai-router, streamly-security-core, sovereign-agentic-network (workspaces), merlyn-memory, sigil, streamly-agent-platform | `npm ci`, then `npm run build` / `typecheck` / `test` where the script exists |
| Python | latticeiq/backend, sentinel, merlyn-commerce, merlyn-ecoms-plane, llm-gateway, merlyn-forge | `pip install -r …`, then `pytest` |
| Cargo | rosetta, sovereign-mcp, deploy-api, sentry, sovereign-agent, sovereign-twin, artificer (+ queue, kafka once fixed) | `cargo build`, `cargo test` |
| Go | latticeiq/scanner-agent | `go build ./...`, `go test ./...` |

Repos with **no test files at all**: merlyn-ecoms-plane, prism, deploy-api,
sovereign-agent-queue, sovereign-agent-kafka, sovereign-twin, artificer,
merlyn-memory, streamly-agent-platform. For these, a build plus a start-up
smoke check is the most PatchLab Internal can verify.

---

## 4. Security audit results

Run on 2026-09-28 with `npm audit --package-lock-only`, `pip-audit` (pinned
files only) and `cargo audit`. Advisory IDs are as reported by each tool.

**npm**

| Repo | High | Moderate | Packages (fix available for all) |
|---|---|---|---|
| merlyn-memory | 3 | 2 | fastify → 5.12.5, find-my-way, fast-uri, undici, uuid → 14.0.2 |
| caer/packages/admin-console | 3 | 3 | browserslist, nanoid, postcss, react-router, react-router-dom, baseline-browser-mapping |
| sovereign-agentic-network | 2 | 1 | fast-uri, find-my-way, fastify |
| streamly-agent-platform | 1 | 3 | brace-expansion, express, body-parser, qs |
| streamly-ai-router | 0 | 3 | express, body-parser, qs |
| caer/packages/orchestrator | 0 | 1 | undici |
| latticeiq/frontend, streamly-security-core | 0 | 0 | — |

**Python**

| File | Vulnerable | Fix |
|---|---|---|
| merlyn-commerce/requirements.txt | python-multipart 0.0.20 (6 advisories) | ≥ 0.0.31 |
| sentinel/apps/proxy/requirements.txt | cryptography 49.0.0 (PYSEC-2026-3552) | ≥ 50.0.0 |
| sovereign-agentic-network/model/fine-tuning/requirements.txt | torch 2.3.1, transformers 4.42.4, datasets 2.20.0, accelerate 0.32.1, requests 2.32.3 (many advisories) | torch ≥ 2.13, transformers ≥ 5.10, datasets ≥ 5.0.1, requests ≥ 2.33; accelerate has no fixed release |
| latticeiq/backend/requirements-lock.txt, merlyn-ecoms-plane | none | — |

The fine-tuning file only runs on a GPU training machine, so it's lower risk
than the services, but the torch and transformers advisories include
unsafe-deserialisation issues that matter when loading third-party models.

Not audited: merlyn-forge and llm-gateway (ranges, no lock, so there's no
fixed version to check), and latticeiq's unpinned `requirements.txt` (its lock
file was audited instead).

**Rust**

| Repo | Result |
|---|---|
| deploy-api | h2 0.4.15, RUSTSEC-2026-0258 → ≥ 0.4.16; plus 2 "unsound" warnings |
| rosetta, sentry, sovereign-mcp, sovereign-agent, sovereign-twin, artificer | clean (sovereign-mcp, sovereign-twin and artificer have no committed lock, so they were resolved fresh for the audit) |
| sovereign-agent-queue, sovereign-agent-kafka | couldn't be audited: the crates don't build (finding 5) |

---

## 5. What this means for PatchLab Internal

Mapping the four goals onto what the survey found:

1. **Dependency and security updates.** There's real work on day one: 9
   repos have advisories, nearly all with fixes. Each fix is a patch PatchLab Internal can
   test before and after in a sandbox and hand over with a report. The npm
   bumps (express, fastify, undici, react-router) are the best first
   candidates: they're common, fixes exist, and most of those repos have a
   build or test script to check against.
2. **Build health.** 22 repos have no CI and subsovereign's CI is stalled, so a nightly "does it still build
   and pass its own tests" run across the estate is the biggest gain for the
   least effort. The two broken Rust crates show it's needed already.
3. **Consistency and drift.** A baseline worth checking for every repo:
   LICENSE, README, CI workflow, lockfile, a supported runtime (no Node 20 or
   Alpine 3.20), a Rust `edition`, and no large binaries outside LFS.
4. **Estate dashboard.** §2 is a first, static version of the dashboard:
   one row per repo with its stack, CI, tests, lockfile, runtime and
   advisories. The tool should regenerate it on a schedule.

Things the design needs to handle:
- Three ecosystems plus Go, with per-package lockfiles (caer) and npm
  workspaces (sovereign-agentic-network).
- Repos that only build next to a sibling (the sovereign-agent crates): the
  manifest needs "check out these repos together".
- Repos with no tests: a build plus a start-up smoke check, and a report that
  says plainly how little it proves.
- Services that need Postgres, Kafka or API keys to start (merlyn-memory,
  merlyn-commerce, sovereign-agent-kafka): checks run with fixtures or stubs,
  never real credentials.

---

## 6. StreamlyApps: subsovereign

`StreamlyApps/subsovereign` is a self-hosted subscription platform (an Adapty
alternative): a TypeScript backend and dashboard, a CLI, and SDKs for Web,
JS, React, React Native, Vega (Fire TV), iOS/tvOS (Swift), Android (Kotlin),
Flutter and Roku. With 850 files and 145 test files, it's the largest and
best-tested repository in the survey, and the most complex to maintain: 9 npm
lockfiles, a Gradle build, a Swift package, and CI that needs a macOS runner.

| | |
|---|---|
| Last commit | 2026-09-28 |
| CI workflows | backend, dashboard, sdks (Ubuntu + macOS, Gradle, `swift test`, `xcodebuild`) |
| Runtimes | Node 20 in CI and in all 3 Dockerfiles (`node:20-alpine`, `node:20-bookworm-slim`); Java 17; Swift tools 5.9 |
| Dependabot / Renovate | none |
| LICENSE | none |

**CI isn't actually running.** The last 8 runs on `main` (7–8 September)
all failed within 3–9 seconds, with no steps, no runner and no logs, so no
test ran. No run has been recorded since 8 September, although `main` has
had commits since then (the latest today). That pattern usually means
Actions is blocked at the account level (a billing or spending limit) or
disabled for the repository. Someone with access to the StreamlyApps
settings needs to check. Until it's fixed, nothing is testing the most
complex repo in the estate.

**npm audit** (per lockfile; "production" excludes devDependencies):

| Package | All deps | Production only | Notes |
|---|---|---|---|
| backend | 5 high, 5 moderate | 1 high, 3 moderate | **nodemailer 6.x → 10.0.12** (email sent to an unintended domain); express, body-parser, qs (moderate). The nodemailer fix is a major version bump, so it needs testing. |
| sdk-vega | 7 high, 3 moderate, 1 low | same | Via the React Native CLI toolchain: `ip` (SSRF), `image-size`, `js-yaml`, `@react-native-community/cli*`. Listed as dependencies, so they ship to anyone installing the SDK. |
| sdk-react-native | 2 high, 8 moderate | clean | Dev tooling only |
| sdk-react-native-sample | 10 moderate | — | Sample app |
| cli, dashboard, sdk-js, sdk-react, sdk-web | clean | clean | |

**Consistency:**
- The Kotlin plugins differ between `sdk-android` (2.0.21) and
  `sdk-android-sample` (2.2.0), and so does `compileSdk` (35 vs 36), so the
  sample isn't testing the SDK on the toolchain the SDK ships with.
- An empty file named `invalid` was committed to the repo root in today's
  commit; it looks accidental.
- Node 20 is end of life (finding 4 applies here too).

**For PatchLab Internal:** subsovereign is the strongest case for the
before/after testing approach. It has a real test suite, but CI hasn't run
any of it for three weeks, and the backend nodemailer fix is a major bump
that needs exactly that kind of check. The macOS-only iOS and tvOS builds are
out of reach of Linux sandboxes, so the tool must say what it could and
couldn't verify.

---

## 7. Method and limits

- Shallow clones (`--depth 1`) of each default branch as of 2026-09-28.
- Stack, manifests, lockfiles, Dockerfiles, CI and test-file counts come from
  the file tree; test counts measure presence, not whether the tests pass.
- No builds or test suites were run, apart from the dependency resolution
  that `cargo audit` needs.
- CI state comes from the latest GitHub Actions runs on each default branch.
- Audits show known advisories at the date above; results change as new
  advisories are published, which is why the tool needs to re-run them on a
  schedule.
