"use strict";
// SAST Studio front-end. Plain browser JS, no framework, no build step.
// All user-facing strings go through t() (see i18n.js) so the UI can switch
// between 中文 and English live.

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
const state = {
  sourceKind: "upload",
  toolsData: null,    // full /api/tools response
  currentJob: null,   // full job object
  pollTimer: null,
  inspect: null,      // {inventory, tools:[{name, applicable, reason}]} for a path
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
  await loadTools();
  await refreshScanList();
}

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
  $("#scan-picker").addEventListener("change", (e) => loadJob(e.target.value));
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
  const picker = $("#scan-picker");
  picker.innerHTML = "";
  data.jobs.forEach((j) => {
    const label = `${j.target.display} · ${t("status." + j.status)}`;
    picker.appendChild(new Option(label.slice(0, 60), j.id));
  });
  const target = selectId || (data.jobs[0] && data.jobs[0].id);
  if (target) {
    picker.value = target;
    await loadJob(target);
  }
}

function startPolling(jobId) {
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    const job = await loadJob(jobId);
    const terminal = ["done", "error", "awaiting_confirmation", "cancelled"];
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
  const inv = job.inventory;
  if (inv && inv.total_files) {
    const langs = Object.keys(inv.languages || {}).slice(0, 4).join(", ");
    const wrapped = langs ? (getLang() === "zh" ? "（" + langs + "）" : " (" + langs + ")") : "";
    meta.appendChild(el("span", null, t("meta.files", { n: inv.total_files, langs: wrapped })));
  }
  if (job.error) meta.appendChild(el("div", "error", job.error));

  renderProgress(job);
  renderConfirmBox(job);
  renderSummary(job.summary || {});
  renderToolRows(job.results || {});
  populateToolFilter(job.results || {});
  renderFindings();
}

function renderConfirmBox(job) {
  const box = $("#confirm-box");
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
  if (job.status === "done") {
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
  const head = el("div", "fhead");
  head.appendChild(el("span", "sev " + f.severity, t("sev." + f.severity)));
  head.appendChild(el("span", "ftool", f.tool));
  head.appendChild(el("span", "ftitle", f.title || f.rule_id || "finding"));
  card.appendChild(head);

  card.appendChild(el("div", "fsevnote", t("sevnote." + f.severity)));
  if (f.message) card.appendChild(el("div", "fmsg", f.message));

  const loc = [f.file, f.start_line ? "L" + f.start_line : ""].filter(Boolean).join(":");
  if (loc) card.appendChild(el("div", "floc", loc));

  const tags = el("div", "ftags");
  (f.cwe || []).forEach((c) => tags.appendChild(el("span", "ftag", c)));
  (f.owasp || []).forEach((o) => tags.appendChild(el("span", "ftag", o)));
  if (f.rule_id && f.rule_id !== f.title) tags.appendChild(el("span", "ftag", f.rule_id));
  if (f.extra && f.extra.match_preview) {
    tags.appendChild(el("span", "ftag", "match: " + f.extra.match_preview));
  }
  if (tags.children.length) card.appendChild(tags);
  return card;
}

// ---------------------------------------------------------------- bootstrap
document.addEventListener("DOMContentLoaded", () => {
  window.onLangChange = () => {
    buildSeverityFilter();
    if (state.toolsData) { renderToolHeader(); renderToolPickers(); }
    updateToolWarnings();
    if (state.inspect) renderInspectPanel(state.inspect);
    const cur = $("#scan-picker").value;
    if (cur) refreshScanList(cur);          // relabel picker + re-render job
    else if (state.currentJob) renderJob(state.currentJob);
  };
  $("#lang-toggle").addEventListener("click",
    () => setLang(getLang() === "zh" ? "en" : "zh"));
  setLang(getLang());   // apply static i18n + toggle label
  init();
});
