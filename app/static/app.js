"use strict";
// SAST Studio front-end. Plain browser JS, no build step, no framework.

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
const state = {
  sourceKind: "upload",
  tools: [],          // [{name, available, kind, requirement, languages, ...}]
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
      // inspection is a path-only concept
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
  $("#path-input").addEventListener("change", inspectProject);  // fires on blur
  $("#tool-checkboxes").addEventListener("change", updateToolWarnings);
}

function wireFilters() {
  const sev = $("#filter-severity");
  SEVERITIES.forEach((s) => sev.appendChild(new Option(s, s)));
  ["#filter-severity", "#filter-tool", "#filter-file"].forEach((id) =>
    $(id).addEventListener("input", renderFindings));
}

// ---------------------------------------------------------------- tools
async function loadTools() {
  const res = await fetch("/api/tools");
  const data = await res.json();
  state.tools = data.tools;

  // header chips
  const bar = $("#tool-status");
  bar.innerHTML = "";
  data.tools.forEach((t) => {
    const chip = el("span", "chip");
    chip.appendChild(el("span", "dot " + (t.available ? "on" : "off")));
    chip.appendChild(el("span", null, t.name));
    chip.title = t.available ? (t.version || "available") : t.install_hint;
    bar.appendChild(chip);
  });

  // checkboxes (with each tool's language/requirement note)
  const box = $("#tool-checkboxes");
  box.innerHTML = "";
  data.tools.forEach((t) => {
    const item = el("div", "tool-item");
    const row = el("label", "tool-check");
    row.dataset.tool = t.name;
    const cb = el("input");
    cb.type = "checkbox";
    cb.value = t.name;
    cb.checked = t.available;
    cb.disabled = !t.available;
    row.appendChild(cb);
    row.appendChild(el("span", null, t.name + (t.available ? "" : " (not installed)")));
    row.appendChild(el("span", "kindtag", t.kind));
    item.appendChild(row);
    item.appendChild(el("div", "tool-req", "needs: " + (t.requirement || "any project")));
    box.appendChild(item);
  });

  // local-path availability
  if (!data.config.allow_local_path) {
    $("#path-note").classList.remove("hidden");
  }
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
  panel.textContent = "Inspecting " + path + " …";
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
    panel.textContent = "Could not inspect: " + e.message;
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
    `📁 ${inv.total_files || 0} files · ${formatBytes(inv.total_bytes)}` +
    (inv.truncated ? " (truncated)" : "")));

  const chips = el("div", "lang-chips");
  Object.entries(inv.languages || {}).slice(0, 8).forEach(([lang, n]) =>
    chips.appendChild(el("span", "lang-chip", `${lang} ${n}`)));
  panel.appendChild(chips);

  const inapplicable = (data.tools || []).filter((t) => !t.applicable);
  if (inapplicable.length) {
    panel.appendChild(el("div", "warn-title", "Won’t apply to this project:"));
    inapplicable.forEach((t) =>
      panel.appendChild(el("div", "warn-item", `• ${t.name}: ${t.reason}`)));
  }
  markInapplicable(data.tools || []);
}

function markInapplicable(tools) {
  const map = {};
  tools.forEach((t) => (map[t.name] = t.applicable));
  document.querySelectorAll(".tool-check").forEach((row) => {
    const applicable = map[row.dataset.tool];
    row.classList.toggle("inapplicable", applicable === false);
  });
}

function clearInapplicableMarks() {
  document.querySelectorAll(".tool-check.inapplicable")
    .forEach((row) => row.classList.remove("inapplicable"));
}

// warn when a *selected* tool won't apply to the inspected project
function updateToolWarnings() {
  const box = $("#tool-warnings");
  if (!state.inspect || state.sourceKind !== "path") {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  const map = {};
  state.inspect.tools.forEach((t) => (map[t.name] = t));
  const bad = selectedTools()
    .map((n) => map[n])
    .filter((t) => t && !t.applicable);
  if (!bad.length) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "";
  box.appendChild(el("div", "tw-title",
    "⚠ Selected tools that won’t find anything here:"));
  bad.forEach((t) => box.appendChild(el("div", "tw-item", `${t.name} — ${t.reason}`)));
}

// ---------------------------------------------------------------- scan
async function startScan() {
  const err = $("#form-error");
  err.classList.add("hidden");
  const tools = selectedTools();
  if (tools.length === 0) return showError("Pick at least one available tool.");

  // 防呆: for an inspected local path, block only if *every* selected tool is
  // inapplicable (otherwise let inapplicable ones report not_applicable).
  if (state.sourceKind === "path" && state.inspect) {
    const map = {};
    state.inspect.tools.forEach((t) => (map[t.name] = t));
    const bad = tools.filter((n) => map[n] && !map[n].applicable);
    if (bad.length === tools.length) {
      return showError(
        "None of the selected tools apply to this project (" + bad.join(", ") +
        "). Pick tools that match its languages/lockfiles.");
    }
  }

  const fd = new FormData();
  fd.append("source_kind", state.sourceKind);
  fd.append("tools", tools.join(","));

  if (state.sourceKind === "upload") {
    const f = $("#file-input").files[0];
    if (!f) return showError("Choose a .zip archive to scan.");
    fd.append("file", f);
  } else if (state.sourceKind === "git") {
    const url = $("#git-input").value.trim();
    if (!url) return showError("Enter a repository URL.");
    fd.append("git_url", url);
  } else if (state.sourceKind === "path") {
    const p = $("#path-input").value.trim();
    if (!p) return showError("Enter a server-local path.");
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
    const label = `${j.target.display} · ${j.status}`;
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
  const STATUS_LABEL = { awaiting_confirmation: "awaiting confirmation" };
  meta.appendChild(el("span", null, `${job.target.kind}: ${job.target.display}`));
  meta.appendChild(el("span", "jstatus " + job.status,
    STATUS_LABEL[job.status] || job.status));
  if (job.stage && job.status === "running") {
    meta.appendChild(el("span", null, "· " + job.stage));
  }
  const inv = job.inventory;
  if (inv && inv.total_files) {
    const langs = Object.keys(inv.languages || {}).slice(0, 4).join(", ");
    meta.appendChild(el("span", null,
      `· ${inv.total_files} files${langs ? " (" + langs + ")" : ""}`));
  }
  if (job.error) meta.appendChild(el("div", "error", job.error));

  renderProgress(job);
  renderConfirmBox(job);
  renderSummary(job.summary || {});
  renderToolRows(job.results || {});
  populateToolFilter(job.results || {});
  renderFindings();
}

// upload/git pause here so the user can review the prepared source
function renderConfirmBox(job) {
  const box = $("#confirm-box");
  if (job.status !== "awaiting_confirmation") {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "";
  box.appendChild(el("div", "cb-title", "Source ready — review before scanning"));

  const inv = job.inventory || {};
  const langs = Object.entries(inv.languages || {}).slice(0, 6)
    .map(([l, n]) => `${l} ${n}`).join(" · ");
  box.appendChild(el("div", "cb-inv",
    `📁 ${inv.total_files || 0} files · ${formatBytes(inv.total_bytes)}` +
    (langs ? " · " + langs : "")));

  const bad = (job.applicability || []).filter((t) => !t.applicable);
  if (bad.length) {
    box.appendChild(el("div", "cb-warn-title",
      "These selected tools won’t find anything here:"));
    bad.forEach((t) => box.appendChild(el("div", "cb-warn", `• ${t.name} — ${t.reason}`)));
  }

  const btns = el("div", "cb-btns");
  const run = el("button", "primary", "Run scan");
  run.addEventListener("click", () => confirmScan(job.id));
  const cancel = el("button", "ghostbtn", "Cancel");
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
    // source is being prepared (clone/extract) — no tool counts yet
    wrap.classList.remove("hidden");
    fill.className = "progress-fill indet";
    fill.style.width = "";
    label.textContent = job.stage || "Preparing…";
    count.textContent = "";
    return;
  }
  if (job.status === "running") {
    wrap.classList.remove("hidden");
    fill.className = "progress-fill";
    fill.style.width = (p.percent || 0) + "%";
    label.textContent = "Scanning… " + (p.running || 0) + " running";
    count.textContent = `${p.finished || 0}/${p.total || 0} tools · ${p.percent || 0}%`;
    return;
  }
  if (job.status === "done") {
    wrap.classList.remove("hidden");
    fill.className = "progress-fill done";
    fill.style.width = "100%";
    label.textContent = "Scan complete";
    count.textContent = `${p.total || 0}/${p.total || 0} tools · 100%`;
    return;
  }
  // error
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
    stat.appendChild(el("span", "l", s));
    box.appendChild(stat);
  });
  const total = el("div", "stat");
  total.appendChild(el("span", "n", String(summary.total || 0)));
  total.appendChild(el("span", "l", "total"));
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
      row.appendChild(el("span", "tstat running", "running"));
      row.appendChild(el("span", "telapsed", elapsedText(r.started_at)));
      box.appendChild(row);
      return;
    }
    if (r.phase === "pending") {
      row.appendChild(el("span", "tstat pending", "queued"));
      box.appendChild(row);
      return;
    }
    // finished
    row.appendChild(el("span", "tstat " + r.status, r.status));
    if (r.status === "ok") {
      row.appendChild(el("span", "thint",
        `${r.summary.total || 0} findings`));
      row.appendChild(el("span", "telapsed", (r.duration_ms || 0) + "ms"));
    } else if (r.status === "unavailable") {
      row.appendChild(el("span", "thint", r.install_hint || ""));
    } else if (r.status === "not_applicable") {
      row.appendChild(el("span", "thint", r.message || "nothing to scan for this tool"));
    } else if (r.error) {
      row.appendChild(el("span", "thint", r.error.slice(0, 120)));
    }
    box.appendChild(row);
  });
}

function populateToolFilter(results) {
  const sel = $("#filter-tool");
  const current = sel.value;
  sel.innerHTML = '<option value="">All tools</option>';
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
        ? "Scanning… findings will appear as tools finish."
        : "No findings match the current filters."));
    return;
  }

  items.forEach((f) => box.appendChild(renderFinding(f)));
}

function renderFinding(f) {
  const card = el("div", "finding " + f.severity);
  const head = el("div", "fhead");
  head.appendChild(el("span", "sev " + f.severity, f.severity));
  head.appendChild(el("span", "ftool", f.tool));
  head.appendChild(el("span", "ftitle", f.title || f.rule_id || "finding"));
  card.appendChild(head);

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

document.addEventListener("DOMContentLoaded", init);
