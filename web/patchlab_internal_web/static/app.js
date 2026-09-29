"use strict";
/* PatchLab Internal front end. Plain DOM, no framework, no build step.
   All server data is inserted as text (never innerHTML). */

const main = document.getElementById("main");
let timers = [];

// ------------------------------------------------------------------ helpers
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

class Unauthorised extends Error {}

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", headers: {} , ...options };
  if (opts.body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  if (opts.method && opts.method !== "GET") opts.headers["X-PatchLabInternal-Request"] = "1";
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (res.status === 401) throw new Unauthorised(data.error || "unauthorised");
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

function toast(message) {
  const t = document.getElementById("toast");
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3500);
}

function every(ms, fn) { const id = setInterval(fn, ms); timers.push(id); return id; }
function clearTimers() { timers.forEach(clearInterval); timers = []; }

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function fmtDuration(s) {
  if (s === null || s === undefined) return "—";
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), r = s % 60;
  return m < 60 ? `${m}m ${r}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

const VERDICT_TEXT = { PASS: "Pass", WARN: "Warning", FAIL: "Fail", ERROR: "Error" };
function verdictBadge(verdict, { active = false, big = false } = {}) {
  if (active) return h("span", { class: `badge v-RUN${big ? " big" : ""}` }, h("span", { class: "spinner", "aria-hidden": "true" }), "Running");
  if (!verdict) return h("span", { class: `badge v-NONE${big ? " big" : ""}` }, "No report");
  return h("span", { class: `badge v-${verdict}${big ? " big" : ""}` }, VERDICT_TEXT[verdict] || verdict);
}
function targetChip(t) {
  return h("span", { class: "chip", title: `${t.image}: ${t.verdict || ""}` },
    h("span", { class: `dot v-${t.verdict || "NONE"}` }), h("span", { class: "label" }, t.image));
}

function emptyState(title, text, action) {
  return h("div", { class: "empty" }, h("h2", {}, title), h("p", {}, text), action || null);
}

function render(...nodes) {
  main.replaceChildren(...nodes.flat().filter(Boolean));
  main.focus({ preventScroll: true });
}

function showError(err) {
  if (err instanceof Unauthorised) return renderLocked(err.message);
  render(h("div", { class: "callout error" }, String(err.message || err)));
}

function renderLocked(message) {
  document.querySelectorAll(".nav a").forEach((a) => a.classList.remove("active"));
  render(h("div", { class: "panel locked" },
    h("h1", {}, "PatchLab Internal is locked"),
    h("p", {}, "Open the link that ", h("code", {}, "patchlab-internal web"), " printed in your terminal. It contains a one-time access token for this session."),
    h("p", { class: "muted small" }, message)));
}

// ------------------------------------------------------------------ router
const routes = [
  [/^#\/runs\/([^/?]+)$/, (m) => runView(decodeURIComponent(m[1]))],
  [/^#\/runs\/?$/, () => runsView()],
  [/^#\/new(\?.*)?$/, (m) => newRunView(new URLSearchParams((m[1] || "").slice(1)))],
  [/^#\/configs\/?$/, () => configsView()],
  [/^#\/config(\?.*)$/, (m) => configView(new URLSearchParams(m[1].slice(1)).get("path"))],
  [/^#\/environment\/?$/, () => environmentView()],
  [/^#\/estate\/?$/, () => estateView()],
  [/^#\/estate\/decision(\?.*)$/, (m) => decisionView(new URLSearchParams(m[1].slice(1)).get("id"))],
  [/^#\/estate\/digest(\?.*)$/, (m) => digestView(new URLSearchParams(m[1].slice(1)).get("date"))],
];

function route() {
  clearTimers();
  const hash = location.hash || "#/runs";
  const section = (hash.match(/^#\/(\w+)/) || [])[1];
  const navKey = { runs: "runs", new: "new", configs: "configs", config: "configs", environment: "environment", estate: "estate" }[section];
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === navKey));
  for (const [re, fn] of routes) {
    const m = hash.match(re);
    if (m) return fn(m).catch(showError);
  }
  location.hash = "#/runs";
}
window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", route);

// ------------------------------------------------------------------ runs list
async function runsView() {
  let filter = "all", search = "";
  const tbody = h("tbody");
  const table = h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Verdict"), h("th", {}, "Run"), h("th", { class: "hide-sm" }, "Targets"),
      h("th", { class: "nowrap" }, "Started"), h("th", { class: "nowrap hide-sm" }, "Duration"))), tbody));
  const count = h("span", { class: "muted small" });
  const listHolder = h("div");
  const filterButtons = ["all", "running", "PASS", "WARN", "FAIL", "ERROR"].map((f) =>
    h("button", { type: "button", "aria-pressed": String(f === filter), onclick: () => { filter = f; filterButtons.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.f === f))); draw(); }, "data-f": f },
      f === "all" ? "All" : f === "running" ? "In progress" : VERDICT_TEXT[f]));
  const searchBox = h("input", { type: "search", placeholder: "Search runs", "aria-label": "Search runs",
    oninput: (e) => { search = e.target.value.toLowerCase(); draw(); } });

  let runs = [];
  function draw() {
    const shown = runs.filter((r) =>
      (filter === "all" || (filter === "running" ? r.active : r.verdict === filter)) &&
      (!search || [r.name, r.patch, r.run_id, ...(r.targets || []).map((t) => t.image)].join(" ").toLowerCase().includes(search)));
    count.textContent = `${shown.length} of ${runs.length}`;
    if (!runs.length) {
      listHolder.replaceChildren(emptyState("No runs yet", "Start one here, or run patchlab_internal from the command line; runs written to the reports folder appear automatically.",
        h("a", { class: "button primary", href: "#/new" }, "New run")));
      return;
    }
    tbody.replaceChildren(...shown.map((r) => h("tr", { class: "link", tabindex: "0",
        onclick: () => { location.hash = `#/runs/${encodeURIComponent(r.run_id)}`; },
        onkeydown: (e) => { if (e.key === "Enter") location.hash = `#/runs/${encodeURIComponent(r.run_id)}`; } },
      h("td", {}, verdictBadge(r.verdict, { active: r.active })),
      h("td", {}, h("div", {}, h("strong", {}, r.name || (r.job && r.job.config ? r.job.config.split(/[\\/]/).pop() : r.run_id))),
        h("div", { class: "muted small" }, r.patch || (r.job && r.job.patch) || ""),
        h("div", { class: "muted small mono" }, r.run_id)),
      h("td", { class: "hide-sm" }, h("div", { class: "row" }, (r.targets || []).map(targetChip))),
      h("td", { class: "nowrap small" }, fmtTime(r.started || (r.job && r.job.started))),
      h("td", { class: "nowrap small hide-sm" }, r.active ? "…" : fmtDuration(r.duration)))));
    listHolder.replaceChildren(shown.length ? table : emptyState("Nothing matches", "Try another filter or search."));
  }

  async function load() {
    const data = await api("/api/runs");
    runs = data.runs;
    draw();
  }

  render(
    h("div", { class: "page-head" }, h("div", { class: "title" }, h("h1", {}, "Runs"), count),
      h("a", { class: "button primary", href: "#/new" }, "New run")),
    h("div", { class: "panel" }, h("div", { class: "filters" }, filterButtons, h("span", { class: "spacer" }), searchBox), listHolder));
  await load();
  every(5000, () => load().catch(() => {}));
}

// ------------------------------------------------------------------ run detail
const TRANSITION = { ok: "unchanged (pass)", regressed: "Regressed", fixed: "Fixed by patch", "still-failing": "Already failing", missing: "Not run" };
const SEV_ORDER = { error: 0, fail: 1, warn: 2, info: 3 };

function checkStatus(c) {
  if (!c) return "—";
  return `${c.passed ? "pass" : c.timed_out ? "timeout" : `fail (${c.exit_code})`}, ${c.duration.toFixed(1)}s`;
}

function fileLink(runId, rel, label) {
  return h("a", { href: `/files/${encodeURIComponent(runId)}/${rel.split("/").map(encodeURIComponent).join("/")}`, target: "_blank", rel: "noopener" }, label);
}

function findingNode(f) {
  const details = f.details || [];
  const list = (items) => h("ul", {}, items.map((d) => h("li", {}, h("code", {}, d))));
  return h("div", { class: `finding ${f.severity}` },
    h("span", { class: `sev ${f.severity}` }, f.severity.toUpperCase()), h("span", { class: "muted" }, `[${f.area}] `), f.message,
    details.length ? (details.length <= 6 ? list(details)
      : h("div", {}, list(details.slice(0, 6)), h("details", {}, h("summary", {}, `${details.length - 6} more`), list(details.slice(6))))) : null);
}

function targetPanel(runId, t) {
  const findings = [...(t.findings || [])].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const pk = t.packages || {};
  const pkRows = [...(pk.upgraded || []).map((p) => [p.name, p.from, p.to]), ...(pk.added || []).map((p) => [p.name, "—", p.version]),
    ...(pk.removed || []).map((p) => [p.name, p.version, "—"])];
  return h("section", { class: "panel" },
    h("div", { class: "target-head" }, h("h2", {}, h("code", {}, t.image)), verdictBadge(t.verdict)),
    h("p", { class: "muted small" }, [t.os, `${fmtDuration(t.duration)}`, t.kept_container ? `kept for debugging: ${t.kept_container}` : null].filter(Boolean).join(" · ")),
    h("h3", {}, "Findings"),
    findings.length ? findings.map(findingNode) : h("p", { class: "muted" }, "No differences between the baseline and the patched system."),
    (t.updates || []).length ? [h("h3", {}, `Updates applied (${t.updates.length})`), h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "KB"), h("th", {}, "Update"), h("th", { class: "hide-sm" }, "Classification"), h("th", {}, "Result"))),
      h("tbody", {}, t.updates.map((u) => h("tr", {}, h("td", { class: "nowrap" }, h("code", {}, u.kb || "—")), h("td", {}, u.title || ""),
        h("td", { class: "hide-sm" }, u.classification || "—"),
        h("td", { class: /^(Succeeded|installed|already)/.test(u.result || "") ? "t-fixed" : "t-regressed" }, u.result || "—"))))))] : null,
    (t.reboots || []).length ? h("p", { class: "muted small" }, `Reboots: ${t.reboots.length} (${t.reboots.map((s) => `${Math.round(s)}s`).join(", ")})`) : null,
    (t.checks || []).length ? [h("h3", {}, "Checks"), h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Check"), h("th", { class: "hide-sm" }, "Category"), h("th", {}, "Baseline"), h("th", {}, "Patched"), h("th", {}, "Change"), h("th", {}, "Logs"))),
      h("tbody", {}, t.checks.map((c) => h("tr", {},
        h("td", {}, c.name, c.critical ? null : h("span", { class: "muted small" }, " (non-critical)")),
        h("td", { class: "hide-sm" }, c.category), h("td", { class: "nowrap small" }, checkStatus(c.before)),
        h("td", { class: "nowrap small" }, checkStatus(c.after)), h("td", { class: `t-${c.transition}` }, TRANSITION[c.transition] || c.transition),
        h("td", { class: "nowrap small" }, [["before", c.before], ["after", c.after]].filter(([, x]) => x && x.log_file)
          .flatMap(([label, x], i) => [i ? " " : null, fileLink(runId, x.log_file, label)])))))))] : null,
    pkRows.length ? h("details", {}, h("summary", {}, `Package changes: ${pkRows.length}`), h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Package"), h("th", {}, "Before"), h("th", {}, "After"))),
      h("tbody", {}, pkRows.map(([n, a, b]) => h("tr", {}, h("td", {}, n), h("td", {}, h("code", {}, a)), h("td", {}, h("code", {}, b)))))))) : null,
    h("h3", {}, "Pipeline"),
    h("div", { class: "stages" }, (t.stages || []).map((s) => h("span", { class: `stage ${s.status}`, title: s.detail || "" }, `${s.name} · ${fmtDuration(s.duration)}`))));
}

async function runView(runId) {
  let data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  let offset = 0;
  const consoleEl = h("pre", { class: "console", "aria-label": "Run output" });
  const consolePanel = h("details", { class: "panel", open: data.active || !data.report ? true : null },
    h("summary", {}, "Console output"), consoleEl);
  const body = h("div");

  async function pullConsole() {
    const c = await api(`/api/runs/${encodeURIComponent(runId)}/console?offset=${offset}`);
    if (c.text) {
      const atBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 40;
      consoleEl.append(c.text);
      if (atBottom || offset === 0) consoleEl.scrollTop = consoleEl.scrollHeight;
    }
    offset = c.offset;
    return c.active;
  }

  function header() {
    const r = data.report || {};
    const job = data.job || {};
    const actions = h("div", { class: "row" });
    if (data.active) {
      actions.append(h("button", { type: "button", class: "danger", onclick: async (e) => {
        e.target.disabled = true;
        try { await api(`/api/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST", body: {} }); toast("Cancelling: sandboxes are being cleaned up"); }
        catch (err) { toast(err.message); e.target.disabled = false; }
      } }, "Cancel run"));
    }
    if (data.report) {
      actions.append(fileLink(runId, "report.html", "HTML report"), " ", fileLink(runId, "report.md", "Markdown"), " ", fileLink(runId, "report.json", "JSON"));
    }
    if (!data.active) {
      actions.append(h("button", { type: "button", class: "danger", onclick: async () => {
        if (!confirm(`Delete run ${runId} and all its logs?`)) return;
        try { await api(`/api/runs/${encodeURIComponent(runId)}`, { method: "DELETE" }); toast("Run deleted"); location.hash = "#/runs"; }
        catch (err) { toast(err.message); }
      } }, "Delete"));
    }
    return [
      h("a", { class: "back", href: "#/runs" }, "← All runs"),
      h("div", { class: "page-head" }, h("div", { class: "title" }, verdictBadge(r.verdict, { active: data.active, big: true }),
        h("h1", {}, r.name || runId)), actions),
      h("div", { class: "panel" }, h("div", { class: "grid-meta" },
        h("div", {}, h("span", {}, "Patch"), (r.patch && r.patch.label) || job.patch || "config default"),
        h("div", {}, h("span", {}, "Target"), data.platform ? `${data.platform} on ${data.provider}` : "—"),
        h("div", {}, h("span", {}, "Started"), fmtTime(r.started || job.started)),
        h("div", {}, h("span", {}, "Duration"), data.active ? "in progress" : fmtDuration(r.duration)),
        h("div", {}, h("span", {}, "Cleanup"), r.cleanup || (data.active ? "pending" : "—")),
        h("div", {}, h("span", {}, "Run ID"), h("code", {}, runId)))),
      r.cancelled ? h("div", { class: "callout" }, "This run was cancelled; results are partial.") : null,
      (!data.active && !data.report) ? h("div", { class: "callout error" }, "The run ended without a report. The console output below shows why.") : null,
    ];
  }

  function draw() {
    body.replaceChildren(...header().filter(Boolean), consolePanel,
      ...(data.report ? (data.report.targets || []).map((t) => targetPanel(runId, t)) : []));
  }

  render(body);
  draw();
  const active = await pullConsole().catch(() => false);
  if (active || data.active) {
    every(2000, async () => {
      try {
        const still = await pullConsole();
        if (!still) {
          clearTimers();
          data = await api(`/api/runs/${encodeURIComponent(runId)}`);
          consolePanel.open = !data.report;
          draw();
          toast(data.report ? `Run finished: ${VERDICT_TEXT[data.report.verdict] || data.report.verdict}` : "Run ended");
        }
      } catch (_) { /* keep polling */ }
    });
  }
}

// ------------------------------------------------------------------ new run
const PATCH_HELP = {
  "source": ["source:fix.patch", "A unified diff applied to the first deployed directory. Paths are relative to the configs folder."],
  "os-packages": ["os-packages or os-packages:openssl,libssl3", "Every pending OS update, or only the listed packages."],
  "package-file": ["package-file:updates/kb5044281.msu", "Vendor packages (.deb/.rpm/.apk, or .msu/.cab/.msi/.msp/.exe on Windows)."],
  "script": ["script:patches/hotfix.sh", "Any script: shell on Linux, PowerShell on Windows."],
  "windows-update": ["windows-update or windows-update:KB5044281", "What Windows Update for Business / Autopatch rings would install, or only the listed KBs."],
};
const CLOUDS = ["aws", "azure", "gcp", "oci"];

async function newRunView(params) {
  const { configs } = await api("/api/configs");
  const valid = configs.filter((c) => c.valid);
  if (!valid.length) {
    return render(h("div", { class: "page-head" }, h("h1", {}, "New run")),
      h("div", { class: "panel" }, emptyState("No configs found", "Put PatchLab Internal config files in the configs folder (see Environment), or change it with patchlab-internal setup --configs-dir.")));
  }
  const select = h("select", { id: "cfg" }, valid.map((c) => h("option", { value: c.path }, `${c.name} — ${c.path}`)));
  if (params.get("config") && valid.some((c) => c.path === params.get("config"))) select.value = params.get("config");
  const summary = h("div");
  const kindSelect = h("select", { id: "kind" });
  const argInput = h("input", { type: "text", id: "arg", autocomplete: "off" });
  const help = h("div", { class: "help" });
  const images = h("div");
  const password = h("input", { type: "password", id: "pw", autocomplete: "off" });
  const pwField = h("div", {}, h("label", { class: "field", for: "pw" }, "Guest administrator password"), password,
    h("div", { class: "help" }, "Passed only to this run's process as PATCHLAB_INTERNAL_GUEST_PASSWORD. Never stored. Leave empty if the server already has it set."));
  const opt = (id, label, text, checked) => h("label", { class: "check", for: id }, h("input", { type: "checkbox", id, checked: checked || null }),
    h("span", {}, h("strong", {}, label), h("br"), h("span", { class: "muted small" }, text)));
  const rollback = opt("rb", "Verify rollback", "Back the patch out afterwards and check the system recovers.", true);
  const keep = opt("keep", "Keep failing sandboxes", "Leave a failed sandbox running for investigation (remove it later from its config page).", false);
  const failWarn = opt("fw", "Treat warnings as failure", "The run's exit status is a failure on WARN too.", false);
  const cloudNote = h("div", { class: "callout", hidden: true },
    "This config clones production assets. The clones hold production data and must run in the isolated subnet from the config. See docs/CLOUD.md before the first run.");
  const submit = h("button", { type: "submit", class: "primary" }, "Start run");

  function current() { return valid.find((c) => c.path === select.value); }
  function refresh() {
    const c = current();
    summary.replaceChildren(h("div", { class: "grid-meta" },
      h("div", {}, h("span", {}, "Target"), `${c.platform} on ${c.provider}`),
      h("div", {}, h("span", {}, "Checks"), c.checks.join(", ")),
      h("div", {}, h("span", {}, "Default patch"), c.patch || "none: choose one")));
    kindSelect.replaceChildren(...(c.patch ? [h("option", { value: "" }, `Config default (${c.patch})`)] : []),
      ...c.patch_kinds.map((k) => h("option", { value: k }, k)));
    images.replaceChildren(...c.images.map((img, i) => h("label", { class: "check", for: `img${i}` },
      h("input", { type: "checkbox", id: `img${i}`, value: img, checked: true }), h("code", {}, img))));
    const needsPassword = c.platform === "windows" && c.provider !== "local";
    pwField.hidden = !needsPassword;
    cloudNote.hidden = !CLOUDS.includes(c.provider);
    refreshKind();
  }
  function refreshKind() {
    const k = kindSelect.value;
    argInput.disabled = !k;
    const [example, text] = PATCH_HELP[k] || ["", "Uses the [patch] table from the config."];
    argInput.placeholder = k ? `argument after "${k}:" (optional for some kinds)` : "";
    help.textContent = k ? `${text} Example: ${example}` : text;
  }
  select.addEventListener("change", refresh);
  kindSelect.addEventListener("change", refreshKind);

  const form = h("form", { class: "panel", onsubmit: async (e) => {
    e.preventDefault();
    const k = kindSelect.value;
    const arg = argInput.value.trim();
    if (k && ["source", "package-file", "script"].includes(k) && !arg) { toast(`${k} needs a file`); argInput.focus(); return; }
    const chosen = [...images.querySelectorAll("input:checked")].map((i) => i.value);
    if (!chosen.length) { toast("Choose at least one target"); return; }
    submit.disabled = true;
    try {
      const res = await api("/api/runs", { method: "POST", body: {
        config: select.value, patch: k ? (arg ? `${k}:${arg}` : k) : null,
        images: chosen.length === current().images.length ? [] : chosen,
        verify_rollback: document.getElementById("rb").checked, keep_on_failure: document.getElementById("keep").checked,
        fail_on_warn: document.getElementById("fw").checked, guest_password: pwField.hidden ? null : password.value || null } });
      location.hash = `#/runs/${encodeURIComponent(res.run_id)}`;
    } catch (err) { showFormError(err); submit.disabled = false; }
  } },
    h("label", { class: "field", for: "cfg" }, "Config"), select, h("div", { class: "help" }, "Configs found in the configs folder."),
    h("div", { style: null }, h("h3", {}, "About this config"), summary),
    cloudNote,
    h("label", { class: "field", for: "kind" }, "Patch"), kindSelect,
    h("label", { class: "field", for: "arg" }, "Patch argument"), argInput, help,
    h("h3", {}, "Targets"), images,
    pwField,
    h("h3", {}, "Options"), rollback, keep, failWarn,
    h("div", { class: "row" }, submit, h("span", { class: "muted small" }, "Runs as a separate patchlab_internal process; you can leave this page.")));

  function showFormError(err) {
    if (err instanceof Unauthorised) return renderLocked(err.message);
    toast(err.message);
  }

  render(h("div", { class: "page-head" }, h("h1", {}, "New run")), form);
  refresh();
}

// ------------------------------------------------------------------ configs
async function configsView() {
  const { configs, root } = await api("/api/configs");
  const rows = configs.map((c) => h("tr", { class: "link", tabindex: "0",
      onclick: () => { location.hash = `#/config?path=${encodeURIComponent(c.path)}`; },
      onkeydown: (e) => { if (e.key === "Enter") location.hash = `#/config?path=${encodeURIComponent(c.path)}`; } },
    h("td", {}, h("strong", {}, c.name || c.path), h("div", { class: "muted small mono" }, c.path)),
    h("td", { class: "nowrap" }, c.valid ? `${c.platform} / ${c.provider}` : h("span", { class: "badge v-FAIL" }, "Invalid")),
    h("td", { class: "hide-sm" }, c.valid ? `${c.images.length} target(s), ${c.checks.length} check(s)` : h("span", { class: "small" }, c.error)),
    h("td", { class: "hide-sm small" }, c.patch || "—")));
  render(h("div", { class: "page-head" }, h("div", { class: "title" }, h("h1", {}, "Configs"), h("span", { class: "muted small" }, root))),
    h("div", { class: "panel" }, configs.length ? h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Config"), h("th", {}, "Platform"), h("th", { class: "hide-sm" }, "Scope"), h("th", { class: "hide-sm" }, "Default patch"))),
      h("tbody", {}, rows)))
      : emptyState("No configs found", "Add PatchLab Internal .toml configs to this folder, or point the front end elsewhere with patchlab-internal setup --configs-dir.")));
}

async function configView(path) {
  const c = await api(`/api/config?path=${encodeURIComponent(path || "")}`);
  const out = h("pre", { class: "console", hidden: true });
  const gcButton = h("button", { type: "button", onclick: async () => {
    if (!confirm("Remove every sandbox, VM or clone that PatchLab Internal left behind for this config's provider? (Not possible while runs are in progress.)")) return;
    gcButton.disabled = true;
    out.hidden = false;
    out.textContent = "Cleaning up…";
    try { const r = await api("/api/gc", { method: "POST", body: { config: c.path } }); out.textContent = r.output || `exit ${r.exit_code}`; }
    catch (err) { out.textContent = err.message; }
    gcButton.disabled = false;
  } }, "Clean up leftovers");
  render(
    h("a", { class: "back", href: "#/configs" }, "← All configs"),
    h("div", { class: "page-head" }, h("div", { class: "title" }, h("h1", {}, c.name || c.path)),
      h("div", { class: "row" }, c.valid ? h("a", { class: "button primary", href: `#/new?config=${encodeURIComponent(c.path)}` }, "Start a run") : null, c.valid ? gcButton : null)),
    c.valid ? h("div", { class: "panel" }, h("div", { class: "grid-meta" },
      h("div", {}, h("span", {}, "Platform"), `${c.platform} on ${c.provider}`),
      h("div", {}, h("span", {}, "Targets"), c.images.join(", ")),
      h("div", {}, h("span", {}, "Checks"), c.checks.join(", ")),
      h("div", {}, h("span", {}, "Default patch"), c.patch || "none"))) : h("div", { class: "callout error" }, c.error),
    out,
    h("div", { class: "panel" }, h("h2", {}, c.path), h("pre", { class: "toml" }, c.text)));
}

// ------------------------------------------------------------------ environment
async function environmentView() {
  const [env, session] = await Promise.all([api("/api/environment"), api("/api/session")]);
  render(h("div", { class: "page-head" }, h("h1", {}, "Environment")),
    h("div", { class: "two-col" },
      h("div", { class: "panel" }, h("h2", {}, "Tools on this machine"), h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Tool"), h("th", {}, "Used for"), h("th", {}, "Status"))),
        h("tbody", {}, env.tools.map((t) => h("tr", {}, h("td", {}, h("code", {}, t.name)), h("td", { class: "small" }, t.purpose),
          h("td", {}, t.path ? h("span", { class: "badge v-PASS", title: t.path }, "Found") : h("span", { class: "badge v-NONE" }, "Not found")))))))),
      h("div", {},
        h("div", { class: "panel" }, h("h2", {}, "Settings"), h("div", { class: "grid-meta" },
          h("div", {}, h("span", {}, "Reports folder"), h("code", {}, session.reports_dir)),
          h("div", {}, h("span", {}, "Configs folder"), h("code", {}, session.configs_dir)),
          h("div", {}, h("span", {}, "Settings file"), h("code", {}, session.settings_file)),
          h("div", {}, h("span", {}, "Parallel runs"), String(session.max_parallel_runs)),
          h("div", {}, h("span", {}, "Versions"), `core ${session.core_version} · web ${session.version} · Python ${env.python}`)),
          h("p", { class: "help" }, "Change these with ", h("code", {}, "patchlab-internal setup"), ".")),
        h("div", { class: "panel" }, h("h2", {}, "Credentials available to runs"),
          h("p", { class: "small muted" }, "Runs inherit the environment this server started with. Cloud CLIs use their own logins."),
          Object.entries(env.secrets).map(([k, v]) => h("div", { class: "row small" }, h("code", {}, k), v ? h("span", { class: "badge v-PASS" }, "Set") : h("span", { class: "badge v-NONE" }, "Not set")))))));
}

// ------------------------------------------------------------------ estate (read-only)
const DECISION_CLASS = { READY: "v-PASS", REVIEW: "v-WARN", BLOCKED: "v-FAIL", INCONCLUSIVE: "v-NONE" };
const DECISION_TEXT = { READY: "Ready", REVIEW: "Needs review", BLOCKED: "Blocked", INCONCLUSIVE: "Inconclusive" };
const HEALTH_CLASS = { healthy: "v-PASS", failing: "v-WARN", broken: "v-FAIL", error: "v-ERROR" };

function decisionBadge(v, big) {
  return h("span", { class: `badge ${DECISION_CLASS[v] || "v-NONE"}${big ? " big" : ""}` }, DECISION_TEXT[v] || v || "—");
}
function healthBadge(p) {
  if (p.unsupported) return h("span", { class: "badge v-NONE", title: p.unsupported }, "Not verified here");
  if (!p.health) return h("span", { class: "badge v-NONE" }, "Not run yet");
  return h("span", { class: `badge ${HEALTH_CLASS[p.health] || "v-NONE"}` }, p.health);
}
function decisionHref(id) { return `#/estate/decision?id=${encodeURIComponent(id)}`; }
function linkRow(href, ...cells) {
  return h("tr", { class: "link", tabindex: "0", onclick: () => { location.hash = href; },
    onkeydown: (e) => { if (e.key === "Enter") location.hash = href; } }, ...cells);
}
function stat(value, label, cls) {
  return h("div", { class: `stat ${cls || ""}` }, h("strong", {}, String(value)), h("span", {}, label));
}
function table(headers, rows) {
  return h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, headers.map(([t, c]) => h("th", { class: c || null }, t)))), h("tbody", {}, rows)));
}

async function estateView() {
  const e = await api("/api/estate");
  const ready = e.decisions.filter((d) => d.verdict === "READY").length;
  const review = e.decisions.filter((d) => d.verdict === "REVIEW").length;
  const blocking = e.packages.reduce((n, p) => n + p.code_blocking.length, 0);
  const healthy = e.packages.filter((p) => p.health === "healthy").length;
  const eol = e.images.filter((i) => i.bases.some((b) => b.support === "eol")).length;
  const unpinned = e.workflows.reduce((n, w) => n + (w.counts["unpinned-action"] || 0), 0);

  const decisions = e.decisions.length ? table([["Verdict"], ["Change"], ["Where", "hide-sm"], ["Kind", "hide-sm"]],
    e.decisions.map((d) => linkRow(decisionHref(d.id),
      h("td", {}, decisionBadge(d.verdict)),
      h("td", {}, h("strong", {}, d.title), h("div", { class: "muted small" }, d.summary)),
      h("td", { class: "hide-sm small" }, d.where),
      h("td", { class: "hide-sm small nowrap" }, d.kind))))
    : emptyState("No changes proposed", "A cycle proposes changes when it finds something it can fix.");

  const packages = table([["Package"], ["Health"], ["Advisories", "hide-sm"], ["Code findings", "hide-sm"]],
    e.packages.map((p) => h("tr", {},
      h("td", {}, h("strong", {}, p.id), h("div", { class: "muted small mono" }, p.commit ? p.commit.slice(0, 10) : "")),
      h("td", {}, healthBadge(p), p.passing_tests ? h("div", { class: "muted small" },
        `${p.passing_tests} passing${p.failing ? `, ${p.failing} failing` : ""}${p.newly_failing.length ? ` (${p.newly_failing.length} new)` : ""}`) : null,
        p.health_error ? h("div", { class: "small" }, p.health_error) : null),
      h("td", { class: "hide-sm small" }, !p.scanned ? "not scanned yet" : p.scan_error && !p.advisories ? `not scanned (${p.scan_error})`
        : p.advisories ? `${p.advisories} (${p.advisories_production} in production code)` : "none",
        p.not_fixable.length ? h("div", {}, `${p.not_fixable.length} with no automatic fix`) : null),
      h("td", { class: "hide-sm small" }, !p.code_scanned ? "not scanned yet"
        : `${Object.values(p.code_counts).reduce((a, b) => a + b, 0)} (${p.code_counts.high || 0} high)` + (p.code_complete ? "" : ", incomplete"),
        p.code_blocking.length ? h("details", {}, h("summary", {}, `${p.code_blocking.length} blocking`),
          p.code_blocking.map((f) => h("div", { class: "finding fail" }, h("span", { class: "sev fail" }, f.tool.toUpperCase()),
            h("code", {}, `${f.file}:${f.line}`), " ", f.message, f.code ? h("div", {}, h("code", {}, f.code)) : null))) : null))));

  const images = table([["Dockerfile"], ["Base images"]], e.images.map((i) => h("tr", {},
    h("td", { class: "small" }, i.id),
    h("td", { class: "small" }, !i.scanned ? "not scanned yet" : i.error ? `not scanned (${i.error})`
      : i.bases.map((b) => h("div", { class: "row" }, h("code", {}, b.image),
        b.support === "eol" ? h("span", { class: "badge v-FAIL", title: b.eol ? `end of life ${b.eol}` : null }, "End of life")
          : b.support === "ok" ? h("span", { class: "badge v-PASS" }, "Supported") : h("span", { class: "badge v-NONE" }, "Unknown"),
        h("span", { class: "muted" }, b.scan_error ? "scan failed" : `${b.fixable} fixable (${b.fixable_high} high)`)))))));

  const workflows = table([["Repo"], ["Findings"]], e.workflows.map((w) => h("tr", {},
    h("td", {}, w.repo),
    h("td", { class: "small" }, Object.entries(w.counts).map(([k, n]) => `${n} ${k}`).join(", ") || "none"))));

  render(
    h("div", { class: "page-head" }, h("div", { class: "title" }, h("h1", {}, "Estate"),
      h("span", { class: "muted small" }, `${e.repos.length} repos · publishing ${e.publish === "draft-pr" ? "draft PRs" : "off (report only)"}`)),
      e.digests.length ? h("a", { class: "button", href: `#/estate/digest?date=${encodeURIComponent(e.digests[0])}` }, `Digest ${e.digests[0]}`) : null),
    h("div", { class: "stats" }, stat(ready, "ready to review", "v-PASS"), stat(review, "need a closer look", "v-WARN"),
      stat(`${healthy}/${e.packages.length}`, "packages healthy"), stat(blocking, "blocking code findings", blocking ? "v-FAIL" : ""),
      stat(eol, "images on end-of-life runtimes", eol ? "v-FAIL" : ""), stat(unpinned, "unpinned CI actions", unpinned ? "v-WARN" : "")),
    e.publish !== "draft-pr" ? h("div", { class: "callout info" },
      "Nothing here has been sent to a repository. Each change was tested in a sandbox; publishing as draft PRs is off until it is switched on.") : null,
    h("div", { class: "panel" }, h("h2", {}, "Proposed changes"), decisions),
    h("div", { class: "panel" }, h("h2", {}, "Packages"), packages),
    h("div", { class: "two-col" },
      h("div", { class: "panel" }, h("h2", {}, "Container images"), images),
      h("div", { class: "panel" }, h("h2", {}, "CI workflows"), workflows,
        e.digests.length ? h("div", {}, h("h3", {}, "Digests"), h("div", { class: "row" },
          e.digests.map((d) => h("a", { href: `#/estate/digest?date=${encodeURIComponent(d)}` }, d)))) : null)),
    h("p", { class: "muted small" }, "Read from ", h("code", {}, e.state_dir), "."));
}

function patchView(text) {
  return h("pre", { class: "diff" }, text.split("\n").map((line) => {
    const c = line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ") ? "meta"
      : line.startsWith("@@") ? "hunk" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "";
    return h("span", { class: c || null }, line || " ");
  }));
}

async function decisionView(id) {
  const x = await api(`/api/estate/decision?id=${encodeURIComponent(id || "")}`);
  const d = x.decision;
  const gate = (d.gate || []).map((g) => h("div", { class: `finding ${g.ok ? "info" : g.kind === "blocker" ? "fail" : "warn"}` },
    h("span", { class: `sev ${g.ok ? "info" : "fail"}` }, g.ok ? "PASS" : "FAIL"), h("strong", {}, g.name), ": ", g.detail,
    (g.details || []).length ? h("ul", {}, g.details.slice(0, 20).map((t) => h("li", {}, h("code", {}, t)))) : null));
  render(
    h("a", { class: "back", href: "#/estate" }, "← Estate"),
    h("div", { class: "page-head" }, h("div", { class: "title" }, h("h1", {}, x.title), decisionBadge(d.verdict, true))),
    h("div", { class: "panel" }, h("p", {}, d.summary),
      h("div", { class: "grid-meta" },
        h("div", {}, h("span", {}, "Tested on"), h("code", {}, x.commit ? x.commit.slice(0, 12) : "—")),
        h("div", {}, h("span", {}, "Labels"), (d.labels || []).join(", ") || "—"),
        h("div", {}, h("span", {}, "State folder"), h("code", {}, x.id))),
      (d.notes || []).length ? h("ul", { class: "small" }, d.notes.map((n) => h("li", {}, n))) : null),
    h("div", { class: "panel" }, h("h2", {}, "Gate"), gate.length ? gate : h("p", { class: "muted" }, "No gate recorded.")),
    x.pr ? h("div", { class: "panel" }, h("h2", {}, "Pull request description"), h("pre", { class: "toml prose" }, x.pr)) : null,
    x.patch ? h("div", { class: "panel" }, h("h2", {}, "Change"), patchView(x.patch)) : null);
}

async function digestView(date) {
  const x = await api(`/api/estate/digest?date=${encodeURIComponent(date || "")}`);
  render(h("a", { class: "back", href: "#/estate" }, "← Estate"),
    h("div", { class: "page-head" }, h("h1", {}, `Digest ${x.date}`)),
    h("div", { class: "panel" }, h("pre", { class: "toml prose" }, x.text)));
}
