# PatchLab Internal roadmap

PatchLab Internal exists to shrink the gap between "a patch is released" and "we know it
won't break us". AI-assisted vulnerability discovery keeps shrinking the time
between disclosure and exploitation, so that gap is now a security risk in its
own right. This roadmap describes how PatchLab Internal goes from a working prototype to
a trusted gate in an organisation's patching process.

It's a proposal. The ordering reflects the value to a Windows-heavy estate
that tests on Hyper-V, runs production on vSphere and patches through
Intune/Autopatch. Change the order to match what hurts most.

---

## 1. Where PatchLab Internal is today (v0.1)

| Area | What works | Evidence level |
|---|---|---|
| Core pipeline | baseline → patch → reboot → verify → rollback → report → teardown; differential verdicts; TAP/JUnit/NUnit per-test diffs; JSON/Markdown/HTML reports | Unit + end-to-end tested (Docker) |
| Linux containers | Docker sandboxes, setup cache, OS package/source/script patches, OS health probes | Tested end to end in CI |
| Windows VMs | Hyper-V (differencing disks, PowerShell Direct), vSphere (linked clones, PowerCLI); Windows Update as Autopatch would install it; SYSTEM-task installer; reboot cycles; DISM uninstall rollback; Windows health probe | Logic, PowerShell 5.1 compatibility and the local pipeline tested; **not yet run on a real hypervisor** |
| Cloud clones | AWS / Azure / GCP / OCI: clone a live asset into an isolated subnet, run commands via each cloud's own channel, exact tag-based teardown | Flows tested with a recording fake CLI; aws/az/oci (and gcloud in CI) command lines replayed against the real CLIs; **no live account runs yet** |
| Front end | Optional web UI: runs, live console, cancel, configs, clean-up; localhost + token security | API + real-browser tests |
| Engineering | Standard-library only; CI on Ubuntu + Windows, Python 3.11–3.13 | CI |

**The biggest gap is proof, not features.** Windows and cloud support are
correct on paper and in simulation, but they have never met a real Hyper-V
host, vCenter or cloud account.

---

## 2. Principles that shape every phase

1. **Differential by default.** Only report what the patch changed. Noise that is always
   there (DCOM 10016, a service that's always stopped) must never block a patch.
2. **Never touch production.** Clones are read-only copies in isolated networks. Every
   resource is tagged and torn down exactly. A failed clean-up is an ERROR, never a silent leak.
3. **Evidence over opinion.** Every verdict links to logs, diffs and the commands that produced them.
4. **Fits existing patching tools.** PatchLab Internal gates Autopatch, SCCM, SSM and Ansible. It doesn't replace them.
5. **Boring dependencies.** The core stays standard-library Python plus the vendors' own CLIs.
   Heavier features (the UI, integrations) are optional packages.
6. **AI assists, humans approve.** AI triages and explains; it never promotes a patch or
   touches production on its own.

---

## 3. Phases at a glance

```
 v0.2 PROVEN          v0.3 WINDOWS ESTATE      v0.4 CONNECTED           v0.5 TEAM SERVICE        v1.0 TRUSTED GATE
 (weeks 0-6)          (weeks 6-14)             (months 3-6)             (months 6-9)             (months 9-12)
 ─────────────        ─────────────────        ─────────────────        ─────────────────        ─────────────────
 first real runs      domain lab topology      vuln-feed triggers       multi-user + SSO         policy-driven gating
 Hyper-V + vSphere    M365 Apps / Edge         scanner → asset map      RBAC + approvals         SLA-backed runs
 one cloud end to     Autopatch via Graph      ITSM change evidence     job queue + workers      fleet readiness view
 end                  (read + pause)           Teams / Slack            audit log                AI triage (assisted)
 isolation probe      app check library        deployment gates         fleet dashboard          signed evidence
 self-hosted CI       warm pools               cost controls            secrets vault            docs site + PyPI
```

---

## 4. v0.2 "Proven": make the existing features real (weeks 0–6)

**Goal:** every advertised target has run successfully on real infrastructure,
and CI proves it again every night.

| # | Work item | Why | Done when |
|---|---|---|---|
| 1 | **First Hyper-V run.** One Windows Server 2022 golden image, monthly update, `--verify-rollback`. | Converts Windows support from "designed" to "working". | PASS on an unpatched image; FAIL injected via a known-bad check; clean teardown. |
| 2 | **First vSphere run** with the same checks (`include = "checks.toml"`). | Production hypervisor. | As above, plus proof that linked clones and snapshots are removed. |
| 3 | **One cloud end to end** (pick the cloud with the most Windows servers). | Proves clone → isolate → test → destroy with real IAM. | Clone of a non-production asset, report, zero tagged resources left. |
| 4 | **Isolation probe before baseline.** From inside each sandbox, try to reach a list of forbidden endpoints (domain controllers, production subnets, internet except update endpoints). Refuse to continue if any answer. | The single biggest risk of cloning production is a clone reaching real systems. | Run aborts with ERROR on a mis-configured subnet; the report shows what was reachable. |
| 5 | **Self-hosted runners** for a nightly job on a Hyper-V host, plus one cloud sandbox account. | GitHub-hosted runners can't run VMs; regressions in the Windows/cloud paths must be caught automatically. | Nightly workflow green; failures open an issue. |
| 6 | **Error-message pass.** Every provider failure (missing permission, bad subnet, agent offline) maps to a one-line cause + fix. | First users hit set-up errors, not patch errors. | A documented message for each failure seen during items 1–3. |
| 7 | **App-consistent copies:** optional VSS (Windows) / fsfreeze (Linux) before cloud snapshots. | Databases on crash-consistent copies spend time in recovery and can mask real results. | Option per config; SQL Server clone boots without crash recovery. |

---

## 5. v0.3 "Windows estate": test what actually breaks (weeks 6–14)

Most painful Windows regressions come from authentication hardening, Office,
printing and line-of-business apps, not from the OS failing to boot.

1. **Multi-VM labs (the most important feature after v0.2).** A target can be a *topology*:
   domain controller + member server + client, cloned or built together on one isolated
   network. Checks run across machines (log on from the client, access a share, Kerberos to
   a web app, print). This is the only way to catch Kerberos/NTLM/Netlogon/certificate-mapping
   enforcement changes before users do.
2. **Microsoft 365 Apps and Edge** as patch kinds (`m365-apps:<channel>`, `edge`):
   Click-to-Run channel updates, with Office automation smoke tests (open/save/macro/add-in).
3. **Autopatch / Intune integration** via Microsoft Graph:
   - *read:* which quality update is about to reach each ring, so PatchLab Internal tests exactly that release;
   - *write (optional, approved):* pause the release for the tenant when PatchLab Internal returns FAIL,
     and attach the report as evidence.
4. **More sources for the same updates:** WSUS/MECM mode (install what's approved for a test
   collection), and hotpatch testing for Windows Server 2025 / Azure Edition.
5. **Check library** of ready-made, versioned Pester suites with sane defaults: IIS sites/app pools,
   SQL Server (connect, agent jobs, backups), AD DS/DNS/DHCP roles, print servers, RDS,
   certificate services, file shares/DFS, common agents (EDR, backup, monitoring).
6. **Boot and security posture probes:** BitLocker recovery triggers, Secure Boot/DBX state,
   TPM, Credential Guard, LSA protection, SMB signing, TLS cipher suites before/after.
7. **Warm pools:** keep N pre-booted clones or checkpointed VMs per golden image, so a run
   starts in seconds instead of minutes, and refresh them after each Patch Tuesday.

---

## 6. v0.4 "Connected": trigger, decide and hand over automatically (months 3–6)

The goal is the "rapid" in rapid patch testing: from advisory to verdict without a human
starting anything.

```
 advisory feeds ──► which assets are affected? ──► pick targets ──► PatchLab Internal run ──► verdict
 (MSRC, CISA KEV,     (Defender VM, Tenable,        (golden image     (parallel,      │
  vendor RSS, NVD,     Qualys, Rapid7, SSM           or clone per      warm pool)      ├─► ITSM change record + evidence
  distro OVAL)         inventory, CMDB)              build/app tier)                   ├─► Teams / Slack card
                                                                                       ├─► SIEM event
                                                                                       └─► deployment gate: release ring 0
                                                                                           (Autopatch, SSM, Azure Update
                                                                                            Manager, Ansible, SCCM)
```

1. **Triggers:** Patch Tuesday schedule (exists), MSRC CVRF API, CISA KEV additions,
   distro security notices, vendor feeds, plus manual "test this KB/CVE now".
2. **Exposure mapping:** read the vulnerability scanner / inventory to decide *which* golden
   images or assets to test, and rank by exposure (internet-facing, KEV-listed, criticality).
3. **Evidence to ITSM:** create or update a ServiceNow/Jira change with verdict, updates
   applied, findings and links. Map PASS/WARN/FAIL to change risk.
4. **Deployment gates:** a small API/CLI (`patchlab_internal gate --release 2026-10 --require PASS`)
   that pipelines and patch tools can call before promoting a release to ring 0.
5. **Cost and safety controls:** per-provider concurrency caps, cost estimate before a run,
   budget limits, maximum clone lifetime, and automatic `gc` on a schedule.
6. **Plugin interfaces** for providers, patch kinds, checks and notifiers, so integrations
   live outside the core (`patchlab-internal-servicenow`, `patchlab-internal-teams`, and so on).

---

## 7. v0.5 "Team service": from one admin's tool to a shared service (months 6–9)

1. **Server mode:** the front end becomes a service with a job queue and **workers** that run
   close to the infrastructure (a worker on each Hyper-V host, or per cloud account and region).
   Workers pull jobs, so no inbound access to hypervisor hosts is needed.
2. **Identity:** OIDC/SAML SSO (Entra ID first), with **RBAC** separating "view reports",
   "run against golden images" and "clone production assets".
3. **Approvals:** cloning a production asset, or pausing an Autopatch release, can require a
   second person. This matches CAB practice.
4. **Audit log:** who ran what, against which asset, what was cloned, and when it was destroyed.
   Exportable to the SIEM.
5. **Secrets:** guest and cloud credentials from Key Vault / Secrets Manager / HashiCorp Vault,
   never environment variables on a shared server.
6. **Fleet view:** patch readiness per build and application tier for the current release,
   history and trends, flaky-check detection, and mean time from release to verdict.

---

## 8. v1.0 "Trusted gate" (months 9–12)

1. **Policy as code** for which assets may be cloned, where, for how long, and what verdict each
   ring requires (for example OPA/Rego or a simple TOML policy).
2. **AI-assisted triage** (assist, never decide):
   - explain a FAIL from the logs, event log and diffs in plain language;
   - match it against Microsoft release-health known issues and vendor advisories;
   - suggest the likely root cause and a rollback or workaround;
   - draft new checks from an application's runbook or documentation, for a human to review;
   - summarise a month's results for CAB.
   Guardrails: read-only access to reports, no production credentials, every suggestion cited
   to evidence, human approval for any action.
3. **Signed evidence:** reports signed and timestamped, so they can serve as audit evidence
   (ISO 27001, SOC 2, Cyber Essentials Plus, NIS2 patching obligations).
4. **Distribution:** PyPI packages, winget/Chocolatey, a container image for the service and
   workers, a documentation site, and a compatibility and deprecation policy.

---

## 9. Beyond v1.0: ideas worth exploring

- **Image patch testing** for containers and golden images: rebuild the base image with
  updates, run the application's test suite against it, and publish the image only on PASS.
- **Linux live-patching** (kpatch, Canonical Livepatch) validated without reboots.
- **Bare-metal and firmware pilots:** orchestrate a small physical pilot ring (drivers,
  BIOS/UEFI, NIC/HBA firmware), since VMs can't reveal hardware-specific breakage.
- **Performance regression detection** with repeated runs and statistical comparison
  instead of single timings.
- **Chaos-style rollback drills:** periodically prove the back-out plan still works on
  current images, independent of any new patch.
- **Data masking for clones:** optional scrubbing of personal data on cloned disks for
  organisations that must not copy production data into test networks.

---

## 10. How to measure progress

| Metric | Today | v0.4 target | v1.0 target |
|---|---|---|---|
| Time from Patch Tuesday release to verdict for all Windows builds | manual, days | < 4 hours | < 2 hours |
| Share of production builds/app tiers with a PatchLab Internal config | 0% | 50% | 90% |
| Regressions found by PatchLab Internal before ring 0 vs after | — | tracked | > 80% before |
| False FAILs (verdict overturned by a human) | — | < 10% | < 5% |
| Resources left behind after runs | 0 in tests | 0 (alerted) | 0 (enforced) |
| Cost per full monthly test cycle | — | measured | budgeted and reported |

---

## 11. Decisions needed from the organisation

1. **First cloud to prove:** which cloud hosts the most critical Windows workloads?
2. **Isolation design:** who owns the isolated test networks and their egress rules (network
   team, cloud platform team)?
3. **Data policy:** may production data be copied into test clones, for how long, and under
   what controls? This decides whether clone mode is used or golden images only.
4. **Change process:** which ITSM tool, and should a PatchLab Internal PASS lower a change's risk
   automatically?
5. **Autopatch write access:** is PatchLab Internal allowed to pause a release on FAIL, or only report?
6. **Hosting:** where the service and workers run (on-premises VM, container platform, cloud).

---

## 12. Immediate next steps (the next two weeks)

1. Merge the CI and review-fix branch once CI is green.
2. Build one Windows Server 2022 golden VHDX and run `examples/windows/hyperv.toml` for real.
3. Write the isolation probe (v0.2 item 4). It protects every later phase.
4. Choose the first cloud and prepare its isolated subnet using `docs/CLOUD.md`.
5. Record every set-up error hit along the way. That list becomes v0.2's "error-message pass".
