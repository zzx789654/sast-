"use strict";
// SAST Studio front-end. Plain browser JS, no framework, no build step.
// All user-facing strings go through t() (see i18n.js) so the UI can switch
// between 中文 and English live.

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
const state = {
  sourceKind: "upload",
  toolsData: null,    // full /api/tools response
  policies: null,     // /api/policies response
  currentJob: null,   // full job object
  pollTimer: null,
  inspect: null,      // {inventory, tools:[{name, applicable, reason}]} for a path
  view: "scan",       // "scan" | "report" | "monitor"
  monTimer: null,
  jobs: [],           // scan history, for the report list
  selectedJob: null,  // id of the report shown on the right
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};

// resolve a per-tool localized string, falling back to a backend value
function reqText(tl) {
  const s = t("tool." + tl.name + ".req");
  return s === "tool." + tl.name + ".req" ? (tl.requirement || "") : s;
}
function toolDesc(name) {
  const s = t("tool." + name + ".desc");
  return s === "tool." + name + ".desc" ? "" : s;
}
function localReason(name, fallback) {
  const s = t("reason." + name);
  return s === "reason." + name ? (fallback || "") : s;
}
function statusLabel(s) {
  const known = { ok: "tstat.ok", unavailable: "tstat.unavailable",
                  not_applicable: "tstat.not_applicable" };
  return known[s] ? t(known[s]) : s;
}

// ---------------------------------------------------------------- init
async function init() {
  wireTabs();
  wireForm();
  wireFilters();
  wireViewNav();
  await loadTools();
  await loadPolicies();
  await refreshScanList();
}

// ---------------------------------------------------------------- policies
async function loadPolicies() {
  const res = await fetch("/api/policies");
  state.policies = await res.json();
  const select = $("#policy-select");
  select.innerHTML = "";
  state.policies.templates.forEach((p) => select.appendChild(new Option(policyLabel(p), p.id)));
  select.value = state.policies.default;
  select.addEventListener("change", renderPolicy);
  renderPolicy();
}

// Each policy rule maps to one boolean field, except retention (a number) and
// pipeline_events (two booleans). One table drives both rendering and reading,
// so the form and the submitted payload cannot drift apart.
const POLICY_FIELDS = {
  critical_block: ["block_critical"],
  high_manual_review: ["high_requires_review"],
  secret_block: ["block_secrets"],
  false_positive_exception: ["exception_requires_owner_reason_expiry"],
  pipeline_events: ["require_pull_request_scan", "require_release_scan"],
};
const POLICY_FIELD_LABEL = {
  require_pull_request_scan: "policy.rule.requirePr",
  require_release_scan: "policy.rule.requireRelease",
};

// Template names/descriptions come from the backend in one language; prefer a
// localized string when we have one, otherwise show what the backend sent.
function policyLabel(policy, suffix) {
  const key = "policy.tpl." + policy.id + (suffix || "");
  const localized = t(key);
  if (localized !== key) return localized;
  return suffix ? policy.description : (policy.name || policy.id);
}

function renderPolicy() {
  if (!state.policies) return;
  const select = $("#policy-select");
  // Relabel options in place so a language switch keeps the current selection.
  Array.from(select.options).forEach((opt) => {
    const tpl = state.policies.templates.find((p) => p.id === opt.value);
    if (tpl) opt.textContent = policyLabel(tpl);
  });
  const selected = state.policies.templates.find((p) => p.id === select.value)
    || state.policies.templates[0];
  $("#policy-desc").textContent = policyLabel(selected, ".desc");
  const box = $("#policy-rules");
  box.innerHTML = "";

  // A policy is judged on the COMBINED findings of every selected tool, so say
  // so once up front — "which tool does this rule belong to?" is the single
  // most common misreading of this panel.
  box.appendChild(el("p", "policy-scope", t("policy.scope")));

  state.policies.rules.forEach((rule) => {
    const row = el("div", "policy-rule-row");

    if (rule.id === "report_retention") {
      const head = el("label", "policy-rule");
      head.appendChild(document.createTextNode(t("policy.rule.report_retention") + ": "));
      const input = document.createElement("input");
      input.type = "number";
      input.id = "policy-rule-report_retention_days";
      input.min = "1";
      input.max = "3650";
      input.value = selected.report_retention_days;
      head.appendChild(input);
      head.appendChild(document.createTextNode(" " + t("policy.days")));
      row.appendChild(head);
      row.appendChild(el("div", "policy-why", t("policy.why.report_retention")));
      box.appendChild(row);
      return;
    }

    (POLICY_FIELDS[rule.id] || []).forEach((field) => {
      const head = el("label", "policy-rule");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.id = "policy-rule-" + field;
      input.checked = Boolean(selected[field]);
      head.appendChild(input);
      head.appendChild(el("span", "policy-rule-title",
        t(POLICY_FIELD_LABEL[field] || "policy.rule." + rule.id)));
      row.appendChild(head);

      // "when X happens -> this scan is judged Y", in plain words.
      // keyed by field name, which is unique across every rule
      const key = "policy.why." + field;
      const why = t(key);
      if (why !== key) row.appendChild(el("div", "policy-why", why));

      // Which tools can actually produce this kind of finding.
      if ((rule.sources || []).length) {
        const src = el("div", "policy-src");
        src.appendChild(document.createTextNode(t("policy.from") + " "));
        rule.sources.forEach((name) => {
          const installed = toolIsAvailable(name);
          const chip = el("span", "policy-srcchip" + (installed ? "" : " off"), name);
          if (!installed) chip.title = t("notInstalled").trim();
          src.appendChild(chip);
        });
        row.appendChild(src);
      }

      // How many findings of this kind the currently shown scan has.
      const hit = currentRuleHits(rule);
      if (hit !== null) {
        row.appendChild(el("div", "policy-hit" + (hit ? " on" : ""),
          t("policy.hits", { n: hit })));
      }
      box.appendChild(row);
    });
  });
}

function toolIsAvailable(name) {
  const tools = (state.toolsData && state.toolsData.tools) || [];
  const tool = tools.find((x) => x.name === name);
  return tool ? tool.available : true;
}

// Findings of this rule's kind in the scan currently shown, so the policy panel
// says what it would mean for *this* project rather than in the abstract.
function currentRuleHits(rule) {
  if (!rule.counter || !state.currentJob) return null;
  const counts = (state.currentJob.policy_evaluation || {}).counts;
  if (counts && counts[rule.counter] !== undefined) return counts[rule.counter];
  const summary = state.currentJob.summary || {};
  return summary[rule.counter] !== undefined ? summary[rule.counter] : null;
}

function readPolicyOverrides() {
  const out = {};
  Object.values(POLICY_FIELDS).forEach((fields) => fields.forEach((field) => {
    const input = $("#policy-rule-" + field);
    if (input) out[field] = input.checked;
  }));
  const retention = $("#policy-rule-report_retention_days");
  if (retention) out.report_retention_days = Number(retention.value);
  return out;
}

// ---------------------------------------------------------------- views
function wireViewNav() {
  document.querySelectorAll(".viewtab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".viewtab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      showView(tab.dataset.view);
    });
  });
  $("#mon-refresh").addEventListener("click", renderMonitor);
  $("#admin-update").addEventListener("click", runToolUpdate);
  $("#admin-restart").addEventListener("click", runRestart);
  $("#report-refresh").addEventListener("click", () => refreshScanList(state.selectedJob));
  $("#export-csv").addEventListener("click", exportCsv);
  $("#export-pdf").addEventListener("click", () => window.print());
}

function showView(view) {
  state.view = view;
  document.querySelectorAll(".viewtab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === view));
  $("#view-scan").classList.toggle("hidden", view !== "scan");
  $("#view-report").classList.toggle("hidden", view !== "report");
  $("#view-monitor").classList.toggle("hidden", view !== "monitor");
  if (view === "monitor") { renderMonitor(); startMonitorPolling(); }
  else stopMonitorPolling();
  if (view === "report") refreshScanList(state.selectedJob);
}

function exportCsv() {
  if (!state.selectedJob) return;
  // A plain navigation lets the browser handle the download + filename.
  window.location.href = `/api/scans/${state.selectedJob}/export.csv`;
}

async function renderMonitor() {
  await loadTools();            // refresh installed versions/availability
  renderMonitorTools();
  await loadMonitorDocker();
  await loadAdminStatus();
}

// ---------------------------------------------------------------- operator
// Updating the scanners and restarting run on the server, so the panel makes
// the state obvious: buttons disable while a job runs, output streams into the
// log, and a restart says plainly that it drops scan history.
async function loadAdminStatus() {
  let d;
  try {
    d = await (await fetch("/api/admin/status")).json();
  } catch (e) {
    return;
  }
  state.admin = d;

  const running = !!d.running;
  const btnUpdate = $("#admin-update");
  const btnRestart = $("#admin-restart");
  if (btnUpdate) btnUpdate.disabled = running;
  if (btnRestart) btnRestart.disabled = running;

  const label = $("#admin-state");
  if (label) {
    label.textContent = running
      ? t("admin.running", { kind: d.kind || "" })
      : (d.ok === true ? t("admin.done")
         : d.ok === false ? t("admin.failed") : "");
    label.className = "admin-state" + (running ? " busy"
      : d.ok === false ? " bad" : d.ok === true ? " good" : "");
  }

  // Say which tools this can actually update, so a pinned binary that needs an
  // image rebuild does not look like a button that silently did nothing.
  const note = $("#admin-updatable");
  if (note) {
    const list = (d.tools_available || []);
    const inPlace = list.filter((x) => x.in_place).map((x) => x.name);
    const pinned = list.filter((x) => !x.in_place).map((x) => x.name);
    note.textContent = "";
    if (inPlace.length) note.textContent += t("admin.canUpdate", { list: inPlace.join(", ") });
    if (pinned.length) note.textContent += " " + t("admin.pinned", { list: pinned.join(", ") });
  }

  const log = $("#admin-log");
  if (log) {
    if (d.log) { log.textContent = d.log; log.classList.remove("hidden"); log.scrollTop = log.scrollHeight; }
    else log.classList.add("hidden");
  }

  // Keep polling only while something is in flight.
  if (running) {
    clearTimeout(state.adminTimer);
    state.adminTimer = setTimeout(loadAdminStatus, 2000);
  }
}

async function runToolUpdate() {
  if (!confirm(t("admin.confirmUpdate"))) return;
  const body = new FormData();
  try {
    const res = await fetch("/api/admin/update-tools", { method: "POST", body });
    const d = await res.json();
    if (!d.started) { alert(d.reason || t("admin.failed")); return; }
  } catch (e) {
    alert(t("admin.failed") + ": " + e.message);
    return;
  }
  loadAdminStatus();
}

async function runRestart() {
  if (!confirm(t("admin.confirmRestart"))) return;
  try {
    const res = await fetch("/api/admin/restart", { method: "POST" });
    const d = await res.json();
    if (!d.restarting) { alert(d.reason || t("admin.failed")); return; }
  } catch (e) {
    // The process may drop the connection as it goes down; that is expected.
  }
  // Poll until the app answers again, then reload so the UI reflects the
  // restarted server rather than showing a stale page.
  const label = $("#admin-state");
  if (label) { label.textContent = t("admin.restarting"); label.className = "admin-state busy"; }
  waitForServer();
}

function waitForServer(attempt) {
  const n = attempt || 0;
  if (n > 60) {
    const label = $("#admin-state");
    if (label) { label.textContent = t("admin.restartSlow"); label.className = "admin-state bad"; }
    return;
  }
  setTimeout(async () => {
    try {
      const r = await fetch("/api/health", { cache: "no-store" });
      if (r.ok) { location.reload(); return; }
    } catch (e) { /* still down */ }
    waitForServer(n + 1);
  }, 1000);
}

function renderMonitorTools() {
  const box = $("#mon-tools");
  box.innerHTML = "";
  const tools = state.toolsData ? state.toolsData.tools : [];
  tools.forEach((tl) => {
    const row = el("div", "mon-tool");
    row.appendChild(el("span", "mt-dot " + (tl.available ? "on" : "off")));
    row.appendChild(el("span", "mt-name", tl.name));
    row.appendChild(el("span", "mt-ver",
      tl.available ? (tl.version || t("mon.installed")) : t("notInstalled").trim()));
    box.appendChild(row);
  });
}

async function loadMonitorDocker() {
  const box = $("#mon-docker");
  let data;
  try {
    data = await (await fetch("/api/system")).json();
  } catch (e) {
    box.innerHTML = "";
    box.appendChild(el("div", "mon-note", t("mon.dockerErr", { msg: e.message })));
    return;
  }
  const d = data.docker || {};
  box.innerHTML = "";
  if (!d.available) {
    box.appendChild(el("div", "mon-note", t("mon.dockerOff")));
    box.appendChild(el("div", "mon-subnote", t("mon.enableHint")));
    if (d.reason) box.appendChild(el("div", "mon-subnote", d.reason));
    return;
  }
  if (!d.containers.length) {
    box.appendChild(el("div", "mon-note", t("mon.noContainers")));
    return;
  }
  box.appendChild(el("div", "mon-subnote", t("cap.hint")));
  const table = el("table", "mon-table");
  const head = el("tr");
  ["col.name", "col.image", "col.state", "col.cpu", "col.mem", "col.net",
   "col.capacity"]
    .forEach((k) => head.appendChild(el("th", null, t(k))));
  table.appendChild(head);
  d.containers.forEach((c) => {
    const tr = el("tr", c.state === "running" ? "running" : "stopped");
    tr.appendChild(el("td", "c-name", c.name));
    tr.appendChild(el("td", "c-img", c.image));
    tr.appendChild(el("td", null, c.status || c.state));
    tr.appendChild(meterCell(c.cpu_pct, c.cpu_pct != null ? c.cpu_pct + "%" : "—"));
    tr.appendChild(meterCell(c.mem_pct, c.mem_used != null
      ? formatBytes(c.mem_used) + (c.mem_limit ? " / " + formatBytes(c.mem_limit) : "")
      : "—"));
    tr.appendChild(el("td", null, c.net_rx != null
      ? formatBytes(c.net_rx) + " / " + formatBytes(c.net_tx) : "—"));
    tr.appendChild(capacityCell(c.capacity));
    table.appendChild(tr);
  });
  box.appendChild(table);
}

// Turn the backend's capacity verdict into a badge plus the concrete reasons,
// so the tab answers "is this container big enough?" rather than just showing
// numbers the reader still has to interpret.
function capacityCell(cap) {
  const td = el("td", "c-cap");
  if (!cap) { td.textContent = "—"; return td; }
  td.appendChild(el("span", "cap-badge cap-" + cap.level, t("cap." + cap.level)));
  (cap.reasons || []).forEach((r) => {
    const key = "cap." + r;
    const text = t(key);
    if (text !== key) td.appendChild(el("div", "cap-why", text));
  });
  return td;
}

function meterCell(pct, text) {
  const td = el("td");
  const wrap = el("div", "meter");
  const bar = el("div", "meter-fill");
  bar.style.width = (pct != null ? Math.min(100, pct) : 0) + "%";
  if (pct != null && pct >= 80) bar.classList.add("hot");
  wrap.appendChild(bar);
  td.appendChild(wrap);
  td.appendChild(el("span", "meter-txt", text));
  return td;
}

function startMonitorPolling() {
  clearInterval(state.monTimer);
  state.monTimer = setInterval(loadMonitorDocker, 3000);
}
function stopMonitorPolling() { clearInterval(state.monTimer); }

function wireTabs() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      state.sourceKind = tab.dataset.kind;
      document.querySelectorAll(".tabpane").forEach((p) => {
        p.classList.toggle("hidden", p.dataset.pane !== state.sourceKind);
      });
      if (state.sourceKind === "path" && $("#path-input").value.trim()) {
        inspectProject();
      } else {
        $("#inspect-panel").classList.add("hidden");
        clearInapplicableMarks();
        updateToolWarnings();
      }
    });
  });
}

function wireForm() {
  $("#start-btn").addEventListener("click", startScan);
  $("#select-all").addEventListener("click", () => {
    document.querySelectorAll(".tool-check input:not(:disabled)")
      .forEach((cb) => (cb.checked = true));
    updateToolWarnings();
  });
  $("#inspect-btn").addEventListener("click", inspectProject);
  $("#path-input").addEventListener("change", inspectProject);
  $("#tool-checkboxes").addEventListener("change", updateToolWarnings);
}

function wireFilters() {
  buildSeverityFilter();
  populateToolFilter({});
  ["#filter-severity", "#filter-tool", "#filter-file"].forEach((id) =>
    $(id).addEventListener("input", renderFindings));
}

function buildSeverityFilter() {
  const sel = $("#filter-severity");
  const current = sel.value;
  sel.innerHTML = "";
  sel.appendChild(new Option(t("filter.allSev"), ""));
  SEVERITIES.forEach((s) => sel.appendChild(new Option(t("sev." + s), s)));
  sel.value = current;
}

// ---------------------------------------------------------------- tools
async function loadTools() {
  const res = await fetch("/api/tools");
  state.toolsData = await res.json();
  renderToolHeader();
  renderToolPickers();
  if (!state.toolsData.config.allow_local_path) {
    $("#path-note").classList.remove("hidden");
  }
}

function renderToolHeader() {
  const bar = $("#tool-status");
  bar.innerHTML = "";
  state.toolsData.tools.forEach((tl) => {
    const chip = el("span", "chip");
    chip.appendChild(el("span", "dot " + (tl.available ? "on" : "off")));
    chip.appendChild(el("span", null, tl.name));
    chip.title = tl.available ? (tl.version || t("chip.available")) : tl.install_hint;
    bar.appendChild(chip);
  });
}

function currentSelection() {
  const boxes = document.querySelectorAll(".tool-check input");
  if (!boxes.length) return null;
  const s = new Set();
  boxes.forEach((cb) => { if (cb.checked) s.add(cb.value); });
  return s;
}

function renderToolPickers() {
  if (!state.toolsData) return;
  const prev = currentSelection();
  const box = $("#tool-checkboxes");
  box.innerHTML = "";
  state.toolsData.tools.forEach((tl) => {
    const item = el("div", "tool-item");
    const row = el("label", "tool-check");
    row.dataset.tool = tl.name;
    const cb = el("input");
    cb.type = "checkbox";
    cb.value = tl.name;
    cb.disabled = !tl.available;
    cb.checked = prev ? prev.has(tl.name) : tl.available;
    row.appendChild(cb);
    row.appendChild(el("span", null, tl.name + (tl.available ? "" : t("notInstalled"))));
    row.appendChild(el("span", "kindtag", tl.kind));
    item.appendChild(row);
    const desc = toolDesc(tl.name);
    if (desc) item.appendChild(el("div", "tool-desc", desc));
    item.appendChild(el("div", "tool-req", t("needs") + reqText(tl)));
    box.appendChild(item);
  });
  if (state.inspect) markInapplicable(state.inspect.tools);
}

function selectedTools() {
  return Array.from(document.querySelectorAll(".tool-check input:checked"))
    .map((cb) => cb.value);
}

// ---------------------------------------------------------------- inspect
function formatBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}

async function inspectProject() {
  if (state.sourceKind !== "path") return;
  const path = $("#path-input").value.trim();
  const panel = $("#inspect-panel");
  if (!path) {
    panel.classList.add("hidden");
    state.inspect = null;
    clearInapplicableMarks();
    updateToolWarnings();
    return;
  }
  panel.className = "inspect-panel loading";
  panel.textContent = t("inspect.inspecting", { path });
  try {
    const fd = new FormData();
    fd.append("source_kind", "path");
    fd.append("local_path", path);
    const res = await fetch("/api/inspect", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "inspect failed");
    state.inspect = data;
    renderInspectPanel(data);
  } catch (e) {
    panel.className = "inspect-panel";
    panel.textContent = t("inspect.failed", { msg: e.message });
    state.inspect = null;
    clearInapplicableMarks();
  }
  updateToolWarnings();
}

function renderInspectPanel(data) {
  const inv = data.inventory || {};
  const panel = $("#inspect-panel");
  panel.className = "inspect-panel";
  panel.innerHTML = "";
  panel.appendChild(el("div", "inv-head",
    "📁 " + t("files.unit", { n: inv.total_files || 0 }) +
    " · " + formatBytes(inv.total_bytes) + (inv.truncated ? " (…)" : "")));

  const chips = el("div", "lang-chips");
  Object.entries(inv.languages || {}).slice(0, 8).forEach(([lang, n]) =>
    chips.appendChild(el("span", "lang-chip", `${lang} ${n}`)));
  panel.appendChild(chips);

  const inapplicable = (data.tools || []).filter((tl) => !tl.applicable);
  if (inapplicable.length) {
    panel.appendChild(el("div", "warn-title", t("inspect.wontApply")));
    inapplicable.forEach((tl) => panel.appendChild(
      el("div", "warn-item", `• ${tl.name}: ${localReason(tl.name, tl.reason)}`)));
  }
  markInapplicable(data.tools || []);
}

function markInapplicable(tools) {
  const map = {};
  tools.forEach((tl) => (map[tl.name] = tl.applicable));
  document.querySelectorAll(".tool-check").forEach((row) => {
    row.classList.toggle("inapplicable", map[row.dataset.tool] === false);
  });
}

function clearInapplicableMarks() {
  document.querySelectorAll(".tool-check.inapplicable")
    .forEach((row) => row.classList.remove("inapplicable"));
}

function updateToolWarnings() {
  const box = $("#tool-warnings");
  if (!state.inspect || state.sourceKind !== "path") {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  const map = {};
  state.inspect.tools.forEach((tl) => (map[tl.name] = tl));
  const bad = selectedTools().map((n) => map[n]).filter((tl) => tl && !tl.applicable);
  if (!bad.length) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "";
  box.appendChild(el("div", "tw-title", t("toolwarn.title")));
  bad.forEach((tl) => box.appendChild(
    el("div", "tw-item", `${tl.name} — ${localReason(tl.name, tl.reason)}`)));
}

// ---------------------------------------------------------------- scan
async function startScan() {
  const err = $("#form-error");
  err.classList.add("hidden");
  const tools = selectedTools();
  if (tools.length === 0) return showError(t("err.noTool"));

  if (state.sourceKind === "path" && state.inspect) {
    const map = {};
    state.inspect.tools.forEach((tl) => (map[tl.name] = tl));
    const bad = tools.filter((n) => map[n] && !map[n].applicable);
    if (bad.length === tools.length) {
      return showError(t("err.allInapplicable", { tools: bad.join(", ") }));
    }
  }

  const fd = new FormData();
  fd.append("source_kind", state.sourceKind);
  fd.append("tools", tools.join(","));
  fd.append("policy", $("#policy-select").value || "standard");
  fd.append("policy_rules", JSON.stringify(readPolicyOverrides()));

  if (state.sourceKind === "upload") {
    const f = $("#file-input").files[0];
    if (!f) return showError(t("err.noZip"));
    fd.append("file", f);
  } else if (state.sourceKind === "git") {
    const url = $("#git-input").value.trim();
    if (!url) return showError(t("err.noUrl"));
    fd.append("git_url", url);
  } else if (state.sourceKind === "path") {
    const p = $("#path-input").value.trim();
    if (!p) return showError(t("err.noPath"));
    fd.append("local_path", p);
  }

  $("#start-btn").disabled = true;
  try {
    const res = await fetch("/api/scans", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "scan failed to start");
    // The results live on the Report tab now, so follow the scan over there.
    showView("report");
    await refreshScanList(data.id);
    startPolling(data.id);
  } catch (e) {
    showError(e.message);
  } finally {
    $("#start-btn").disabled = false;
  }
}

function showError(msg) {
  const err = $("#form-error");
  err.textContent = msg;
  err.classList.remove("hidden");
}

async function refreshScanList(selectId) {
  const res = await fetch("/api/scans");
  const data = await res.json();
  state.jobs = data.jobs;
  const target = selectId || (data.jobs[0] && data.jobs[0].id);
  state.selectedJob = target || null;
  renderReportList();
  if (target) await loadJob(target);
}

function renderReportList() {
  const box = $("#report-list");
  if (!box) return;
  box.innerHTML = "";
  if (!state.jobs || !state.jobs.length) {
    box.appendChild(el("p", "mon-note", t("report.empty")));
    return;
  }
  state.jobs.forEach((j) => {
    const row = el("button", "report-row" +
      (j.id === state.selectedJob ? " active" : ""));
    row.appendChild(el("div", "rr-target", shortTarget(j.target.display)));

    const meta = el("div", "rr-meta");
    meta.appendChild(el("span", "jstatus " + j.status, t("status." + j.status)));
    if (j.decision) {
      meta.appendChild(el("span", "policy-decision gate-" + j.decision,
        t("policy.decision." + j.decision)));
    }
    row.appendChild(meta);

    const s = j.summary || {};
    const counts = el("div", "rr-counts");
    ["critical", "high", "medium", "low"].forEach((sev) => {
      if (s[sev]) counts.appendChild(el("span", "rr-c " + sev, `${s[sev]}`));
    });
    if (!counts.children.length) counts.appendChild(el("span", "rr-c none", "0"));
    row.appendChild(counts);

    row.appendChild(el("div", "rr-time", localTime(j.finished_at || j.created_at)));
    row.addEventListener("click", () => {
      state.selectedJob = j.id;
      renderReportList();
      loadJob(j.id);
    });
    box.appendChild(row);
  });
}

function shortTarget(display) {
  const s = String(display || "");
  return s.length > 42 ? "…" + s.slice(-41) : s;
}

function localTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

//: Severity order and share for the summary bar at the top of a report.
function renderSevBar(job) {
  const wrap = $("#sev-bar-wrap");
  if (!wrap) return;
  const s = job.summary || {};
  const order = ["critical", "high", "medium", "low", "info", "unknown"];
  const total = order.reduce((n, k) => n + (s[k] || 0), 0);
  if (!total) { wrap.classList.add("hidden"); return; }

  wrap.classList.remove("hidden");
  const bar = $("#sev-bar");
  const legend = $("#sev-bar-legend");
  bar.innerHTML = "";
  legend.innerHTML = "";
  bar.setAttribute("aria-label", t("sevbar.label", { n: total }));

  order.forEach((sev) => {
    const n = s[sev] || 0;
    if (!n) return;
    const pct = (n / total) * 100;
    const seg = el("div", "sev-seg " + sev);
    seg.style.width = pct.toFixed(2) + "%";
    seg.title = `${t("sev." + sev)}: ${n} (${pct.toFixed(1)}%)`;
    bar.appendChild(seg);

    const item = el("span", "sev-leg");
    item.appendChild(el("span", "sev-dot " + sev));
    item.appendChild(document.createTextNode(`${t("sev." + sev)} ${n}`));
    legend.appendChild(item);
  });
  legend.appendChild(el("span", "sev-leg total", t("sevbar.total", { n: total })));
}

function startPolling(jobId) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    const job = await loadJob(jobId);
    const terminal = ["done", "error", "awaiting_confirmation", "cancelled",
                      "policy_review", "blocked"];
    if (job && terminal.includes(job.status)) {
      clearInterval(state.pollTimer);
      refreshScanList(jobId);
    }
  }, 1000);
}

async function loadJob(jobId) {
  if (!jobId) return null;
  const res = await fetch("/api/scans/" + jobId);
  if (!res.ok) return null;
  const job = await res.json();
  state.currentJob = job;
  renderJob(job);
  return job;
}

// ---------------------------------------------------------------- render
function renderJob(job) {
  const meta = $("#scan-meta");
  meta.innerHTML = "";
  meta.appendChild(el("span", null, `${job.target.kind}: ${job.target.display}`));
  meta.appendChild(el("span", "jstatus " + job.status, t("status." + job.status)));
  if (job.policy) {
    // Localize via the template id; a customized policy keeps the "_custom"
    // suffix, so fall back to its base template's label.
    const baseId = String(job.policy_id || "").replace(/_custom$/, "");
    const key = "policy.tpl." + baseId;
    const localized = t(key);
    const name = localized !== key ? localized : (job.policy.name || job.policy_id);
    meta.appendChild(el("span", "policy-pill", t("policy.pill", { name })));
  }
  if (job.policy_evaluation && job.policy_evaluation.decision) {
    const decision = job.policy_evaluation.decision;
    const pill = el("span", "policy-decision gate-" + decision,
      t("policy.gate", { decision: t("policy.decision." + decision) }));
    meta.appendChild(pill);
    const excepted = (job.policy_evaluation.counts || {}).excepted;
    if (excepted) meta.appendChild(el("span", "policy-pill", t("policy.excepted", { n: excepted })));
  }
  const inv = job.inventory;
  if (inv && inv.total_files) {
    const langs = Object.keys(inv.languages || {}).slice(0, 4).join(", ");
    const wrapped = langs ? (getLang() === "zh" ? "（" + langs + "）" : " (" + langs + ")") : "";
    meta.appendChild(el("span", null, t("meta.files", { n: inv.total_files, langs: wrapped })));
  }
  if (job.error) meta.appendChild(el("div", "error", job.error));

  renderProgress(job);
  renderSevBar(job);
  renderConfirmBox(job);
  renderSummary(job.summary || {});
  renderToolRows(job.results || {});
  populateToolFilter(job.results || {});
  renderFindings();
}

function renderConfirmBox(job) {
  const box = $("#confirm-box");
  if (job.status === "policy_review") {
    box.classList.remove("hidden");
    box.innerHTML = "";
    box.appendChild(el("div", "cb-title", t("policy.review.title")));
    const refs = (job.policy_evaluation || {}).manual_review_findings || [];
    refs.forEach((f) => box.appendChild(el("div", "cb-warn", findingRefLabel(f))));
    const reviewer = document.createElement("input");
    reviewer.id = "policy-reviewer";
    reviewer.placeholder = t("policy.review.reviewer");
    reviewer.required = true;
    const note = document.createElement("textarea");
    note.id = "policy-review-note";
    note.placeholder = t("policy.review.note");
    note.required = true;
    box.appendChild(reviewer);
    box.appendChild(note);
    const btns = el("div", "cb-btns");
    const approve = el("button", "primary", t("policy.review.approve"));
    approve.addEventListener("click", () => submitPolicyReview(job.id, "approve"));
    const reject = el("button", "ghostbtn", t("policy.review.reject"));
    reject.addEventListener("click", () => submitPolicyReview(job.id, "reject"));
    btns.appendChild(approve);
    btns.appendChild(reject);
    box.appendChild(btns);
    return;
  }
  if (job.status === "blocked") {
    renderBlockedBox(job, box);
    return;
  }
  if (job.status !== "awaiting_confirmation") {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "";
  box.appendChild(el("div", "cb-title", t("confirm.title")));

  const inv = job.inventory || {};
  const langs = Object.entries(inv.languages || {}).slice(0, 6)
    .map(([l, n]) => `${l} ${n}`).join(" · ");
  box.appendChild(el("div", "cb-inv",
    "📁 " + t("files.unit", { n: inv.total_files || 0 }) + " · " +
    formatBytes(inv.total_bytes) + (langs ? " · " + langs : "")));

  const bad = (job.applicability || []).filter((tl) => !tl.applicable);
  if (bad.length) {
    box.appendChild(el("div", "cb-warn-title", t("confirm.wontApply")));
    bad.forEach((tl) => box.appendChild(
      el("div", "cb-warn", `• ${tl.name} — ${localReason(tl.name, tl.reason)}`)));
  }

  const btns = el("div", "cb-btns");
  const run = el("button", "primary", t("confirm.run"));
  run.addEventListener("click", () => confirmScan(job.id));
  const cancel = el("button", "ghostbtn", t("confirm.cancel"));
  cancel.addEventListener("click", () => cancelScan(job.id));
  btns.appendChild(run);
  btns.appendChild(cancel);
  box.appendChild(btns);
}

function findingRefLabel(f) {
  const where = f.file ? ` ${f.file}:${f.start_line || ""}` : "";
  return `${t("sev." + f.severity)} ${f.tool} ${f.rule_id}${where}`;
}

async function submitPolicyReview(id, decision) {
  const reviewer = $("#policy-reviewer").value.trim();
  const note = $("#policy-review-note").value.trim();
  if (!reviewer || !note) { showError(t("policy.review.required")); return; }
  const fd = new FormData();
  fd.append("decision", decision);
  fd.append("reviewer", reviewer);
  fd.append("note", note);
  const res = await fetch(`/api/scans/${id}/review`, { method: "POST", body: fd });
  if (res.ok) await loadJob(id);
  else showError((await res.json()).detail || t("policy.review.failed"));
}

// A blocked scan can still be unblocked by recording an auditable, time-limited
// false-positive exception for the finding that blocked it.
function renderBlockedBox(job, box) {
  box.classList.remove("hidden");
  box.innerHTML = "";
  box.appendChild(el("div", "cb-title", t("policy.blocking.title")));
  const refs = (job.policy_evaluation || {}).blocking_findings || [];
  refs.forEach((f) => {
    const row = el("div", "cb-warn", findingRefLabel(f) + " ");
    const btn = el("button", "linkbtn", t("policy.except.btn"));
    btn.addEventListener("click", () => renderExceptionForm(job, f, box));
    row.appendChild(btn);
    box.appendChild(row);
  });
  const review = (job.policy_evaluation || {}).review;
  if (review) {
    box.appendChild(el("div", "cb-inv", t("policy.reviewedBy", {
      reviewer: review.reviewer,
      decision: t("policy.review." + (review.decision === "approve" ? "approve" : "reject")),
      note: review.note,
    })));
  }
}

function renderExceptionForm(job, finding, box) {
  box.innerHTML = "";
  box.appendChild(el("div", "cb-title", t("policy.except.title")));
  box.appendChild(el("div", "cb-warn", findingRefLabel(finding)));
  const owner = document.createElement("input");
  owner.id = "exc-owner";
  owner.placeholder = t("policy.except.owner");
  const reason = document.createElement("textarea");
  reason.id = "exc-reason";
  reason.placeholder = t("policy.except.reason");
  const expires = document.createElement("input");
  expires.id = "exc-expires";
  expires.type = "date";
  expires.title = t("policy.except.expires");
  box.appendChild(owner);
  box.appendChild(reason);
  box.appendChild(expires);
  const btns = el("div", "cb-btns");
  const submit = el("button", "primary", t("policy.except.submit"));
  submit.addEventListener("click", () => submitException(job.id, finding));
  const cancel = el("button", "ghostbtn", t("policy.except.cancel"));
  cancel.addEventListener("click", () => renderBlockedBox(job, box));
  btns.appendChild(submit);
  btns.appendChild(cancel);
  box.appendChild(btns);
}

async function submitException(id, finding) {
  const owner = $("#exc-owner").value.trim();
  const reason = $("#exc-reason").value.trim();
  const expires = $("#exc-expires").value;
  if (!owner || !reason || !expires) { showError(t("policy.except.required")); return; }
  const fd = new FormData();
  fd.append("tool", finding.tool);
  fd.append("rule_id", finding.rule_id || "");
  fd.append("file", finding.file || "");
  if (finding.start_line !== null && finding.start_line !== undefined) {
    fd.append("start_line", finding.start_line);
  }
  fd.append("owner", owner);
  fd.append("reason", reason);
  fd.append("expires_at", expires);
  const res = await fetch(`/api/scans/${id}/exceptions`, { method: "POST", body: fd });
  if (res.ok) await loadJob(id);
  else showError((await res.json()).detail || t("policy.except.failed"));
}

async function confirmScan(id) {
  const res = await fetch(`/api/scans/${id}/confirm`, { method: "POST" });
  if (res.ok) {
    await loadJob(id);
    startPolling(id);
  }
}

async function cancelScan(id) {
  await fetch(`/api/scans/${id}/cancel`, { method: "POST" });
  await refreshScanList(id);
}

function renderProgress(job) {
  const wrap = $("#progress-wrap");
  const fill = $("#progress-fill");
  const label = $("#progress-label");
  const count = $("#progress-count");
  const p = job.progress || {};

  if (job.status === "queued" ||
      (job.status === "running" && (p.total || 0) === 0)) {
    wrap.classList.remove("hidden");
    fill.className = "progress-fill indet";
    fill.style.width = "";
    label.textContent = t("progress.preparing");
    count.textContent = "";
    return;
  }
  if (job.status === "running") {
    wrap.classList.remove("hidden");
    fill.className = "progress-fill";
    fill.style.width = (p.percent || 0) + "%";
    label.textContent = t("progress.scanning", { n: p.running || 0 });
    count.textContent = t("progress.count",
      { f: p.finished || 0, t: p.total || 0, p: p.percent || 0 });
    return;
  }
  // policy_review / blocked mean the tools finished and the gate decided,
  // so the bar stays at 100% rather than disappearing.
  if (["done", "policy_review", "blocked"].includes(job.status)) {
    wrap.classList.remove("hidden");
    fill.className = "progress-fill done";
    fill.style.width = "100%";
    label.textContent = t("progress.complete");
    count.textContent = t("progress.count",
      { f: p.total || 0, t: p.total || 0, p: 100 });
    return;
  }
  wrap.classList.add("hidden");
}

function elapsedText(startedIso) {
  if (!startedIso) return "";
  const secs = Math.max(0, (Date.now() - Date.parse(startedIso)) / 1000);
  return secs.toFixed(secs < 10 ? 1 : 0) + "s";
}

function renderSummary(summary) {
  const box = $("#summary");
  box.innerHTML = "";
  SEVERITIES.slice(0, 5).forEach((s) => {
    const stat = el("div", "stat " + s);
    stat.appendChild(el("span", "n", String(summary[s] || 0)));
    stat.appendChild(el("span", "l", t("sev." + s)));
    box.appendChild(stat);
  });
  const total = el("div", "stat");
  total.appendChild(el("span", "n", String(summary.total || 0)));
  total.appendChild(el("span", "l", t("stat.total")));
  box.appendChild(total);
}

function renderToolRows(results) {
  const box = $("#tool-results");
  box.innerHTML = "";
  Object.values(results).forEach((r) => {
    const row = el("div", "tool-row");
    row.appendChild(el("span", "tname", r.tool));

    if (r.phase === "running") {
      row.appendChild(el("span", "spinner"));
      row.appendChild(el("span", "tstat running", t("phase.running")));
      row.appendChild(el("span", "telapsed", elapsedText(r.started_at)));
      box.appendChild(row);
      return;
    }
    if (r.phase === "pending") {
      row.appendChild(el("span", "tstat pending", t("phase.queued")));
      box.appendChild(row);
      return;
    }
    row.appendChild(el("span", "tstat " + r.status, statusLabel(r.status)));
    if (r.status === "ok") {
      row.appendChild(el("span", "thint", t("findings.count", { n: r.summary.total || 0 })));
      row.appendChild(el("span", "telapsed", (r.duration_ms || 0) + "ms"));
    } else if (r.status === "unavailable") {
      row.appendChild(el("span", "thint", r.install_hint || ""));
    } else if (r.status === "not_applicable") {
      row.appendChild(el("span", "thint",
        localReason(r.tool, r.message) || t("tstat.notApplicableFallback")));
    } else if (r.error) {
      row.appendChild(el("span", "thint", r.error.slice(0, 120)));
    }
    box.appendChild(row);
  });
}

function populateToolFilter(results) {
  const sel = $("#filter-tool");
  const current = sel.value;
  sel.innerHTML = "";
  sel.appendChild(new Option(t("filter.allTools"), ""));
  Object.keys(results).forEach((name) => sel.appendChild(new Option(name, name)));
  sel.value = current;
}

function allFindings(job) {
  const out = [];
  Object.values(job.results || {}).forEach((r) =>
    (r.findings || []).forEach((f) => out.push(f)));
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  return out.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

function renderFindings() {
  const box = $("#findings");
  box.innerHTML = "";
  if (!state.currentJob) return;
  const fSev = $("#filter-severity").value;
  const fTool = $("#filter-tool").value;
  const fFile = $("#filter-file").value.toLowerCase();

  const items = allFindings(state.currentJob).filter((f) =>
    (!fSev || f.severity === fSev) &&
    (!fTool || f.tool === fTool) &&
    (!fFile || (f.file || "").toLowerCase().includes(fFile)));

  if (items.length === 0) {
    box.appendChild(el("div", "empty",
      state.currentJob.status === "running"
        ? t("findings.scanning") : t("findings.emptyFiltered")));
    return;
  }
  items.forEach((f) => box.appendChild(renderFinding(f)));
}

function renderFinding(f) {
  const card = el("div", "finding " + f.severity);
  const x = f.extra || {};

  // ---- header: severity, tool, title -------------------------------------
  const head = el("div", "fhead");
  head.appendChild(el("span", "sev " + f.severity, t("sev." + f.severity)));
  head.appendChild(el("span", "ftool", f.tool));
  head.appendChild(el("span", "ftitle", f.title || f.rule_id || t("find.untitled")));
  card.appendChild(head);
  card.appendChild(el("div", "fsevnote", t("sevnote." + f.severity)));

  const parts = splitRemediation(f.message || "");

  // ---- section 1: why this is a problem ----------------------------------
  card.appendChild(fieldBlock("fwhy", t("find.why"), parts.cause));

  // ---- section 2: how to fix it ------------------------------------------
  card.appendChild(fieldBlock("ffix", t("find.howToFix"), parts.fix || packageFixText(x)));

  // ---- section 3: where it is --------------------------------------------
  const loc = [f.file, f.start_line ? "L" + f.start_line : ""].filter(Boolean).join(":");
  card.appendChild(fieldBlock("floc", t("find.location"), loc, true));

  // Dependency findings point at a package, not a line of code.
  if (x.package) {
    const pkg = el("div", "fpkg");
    pkg.appendChild(el("span", "fpkg-name", x.package));
    const installed = x.installed_version || x.version;
    if (installed) pkg.appendChild(el("span", "fpkg-ver", t("find.installed", { v: installed })));
    if (x.vulnerable_range || x.range) {
      pkg.appendChild(el("span", "fpkg-range",
        t("find.vulnRange", { r: x.vulnerable_range || x.range })));
    }
    if (x.fixed_version) {
      pkg.appendChild(el("span", "fpkg-fix", t("find.fixedIn", { v: x.fixed_version })));
    } else if (x.fix_available === false) {
      pkg.appendChild(el("span", "fpkg-nofix", t("find.noFix")));
    }
    card.appendChild(pkg);
  }

  // Code findings: show the offending source line(s) the scanner reported.
  if (x.snippet) {
    const pre = el("pre", "fsnippet");
    pre.appendChild(el("code", null, x.snippet));
    if (f.start_line) pre.setAttribute("data-start", "L" + f.start_line);
    card.appendChild(pre);
  }

  // ---- identifier tags: CWE / OWASP / CVE / rule --------------------------
  const tags = el("div", "ftags");
  (f.cwe || []).forEach((c) => tags.appendChild(idTag("cwe", c)));
  (f.owasp || []).forEach((o) => tags.appendChild(idTag("owasp", o)));
  cveIds(f).forEach((c) => tags.appendChild(idTag("cve", c)));
  if (f.rule_id && f.rule_id !== f.title) tags.appendChild(idTag("rule", f.rule_id));
  if (x.match_preview) tags.appendChild(idTag("match", "match: " + x.match_preview));
  if (tags.children.length) card.appendChild(tags);
  return card;
}

// A labelled block. Scanners differ in what they report, so a field with no
// data is rendered empty rather than dropped: a blank "how to fix" is itself
// information (this tool did not tell us), and keeps every card the same shape.
function fieldBlock(cls, label, value, inline) {
  const box = el("div", "ffield " + cls + (inline ? " inline" : ""));
  box.appendChild(el("span", "flabel", label));
  const v = (value || "").trim();
  box.appendChild(v ? el("span", "fvalue", v)
                    : el("span", "fvalue empty", t("find.notProvided")));
  return box;
}

// Bearer (and some semgrep rules) pack cause and remedy into one markdown
// blob: "## Description ... ## Remediations ...". Split it so each half lands
// under the right heading instead of one unreadable wall of text.
function splitRemediation(message) {
  const m = message.split(/##\s*Remediation[s]?\s*/i);
  const cause = (m[0] || "").replace(/##\s*Description\s*/i, "").trim();
  const fix = (m[1] || "").trim();
  return { cause, fix };
}

// Dependency scanners express the fix as a version, not prose.
function packageFixText(x) {
  if (x.fixed_version) return t("find.upgradeTo", { v: x.fixed_version });
  if (x.resolution) return x.resolution;
  if (x.fix_available === true) return t("find.fixAvailable");
  if (x.fix_available === false) return t("find.noFixYet");
  return "";
}

// CVE/GHSA ids are not a first-class field; they arrive in the rule id or the
// advisory links, so pull them out for display as their own tags.
function cveIds(f) {
  const found = new Set();
  const scan = [f.rule_id || ""].concat(f.references || []);
  scan.forEach((s) => {
    const m = String(s).match(/(CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})/gi);
    // CVE ids are conventionally upper-case, GHSA ids lower-case.
    if (m) m.forEach((id) => found.add(
      /^cve-/i.test(id) ? id.toUpperCase() : id.toLowerCase()));
  });
  return Array.from(found);
}

function idTag(kind, text) {
  const tag = el("span", "ftag ftag-" + kind, text);
  return tag;
}

// ---------------------------------------------------------------- bootstrap
document.addEventListener("DOMContentLoaded", () => {
  window.onLangChange = () => {
    buildSeverityFilter();
    if (state.toolsData) { renderToolHeader(); renderToolPickers(); }
    if (state.policies) renderPolicy();
    updateToolWarnings();
    if (state.inspect) renderInspectPanel(state.inspect);
    renderReportList();                     // relabel status/verdict chips
    if (state.currentJob) renderJob(state.currentJob);
    if (state.view === "monitor") { renderMonitorTools(); loadMonitorDocker(); }
  };
  $("#lang-toggle").addEventListener("click",
    () => setLang(getLang() === "zh" ? "en" : "zh"));
  setLang(getLang());   // apply static i18n + toggle label
  init();
});
