"use strict";
// SAST Studio front-end. Plain browser JS, no build step, no framework.

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
const state = {
  sourceKind: "upload",
  tools: [],          // [{name, available, kind, install_hint, version}]
  currentJob: null,   // full job object
  pollTimer: null,
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
    });
  });
}

function wireForm() {
  $("#start-btn").addEventListener("click", startScan);
  $("#select-all").addEventListener("click", () => {
    document.querySelectorAll(".tool-check input:not(:disabled)")
      .forEach((cb) => (cb.checked = true));
  });
  $("#scan-picker").addEventListener("change", (e) => loadJob(e.target.value));
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

  // checkboxes
  const box = $("#tool-checkboxes");
  box.innerHTML = "";
  data.tools.forEach((t) => {
    const row = el("label", "tool-check");
    const cb = el("input");
    cb.type = "checkbox";
    cb.value = t.name;
    cb.checked = t.available;
    cb.disabled = !t.available;
    row.appendChild(cb);
    const span = el("span", null, t.name + (t.available ? "" : " (not installed)"));
    row.appendChild(span);
    row.appendChild(el("span", "kindtag", t.kind));
    box.appendChild(row);
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

// ---------------------------------------------------------------- scan
async function startScan() {
  const err = $("#form-error");
  err.classList.add("hidden");
  const tools = selectedTools();
  if (tools.length === 0) return showError("Pick at least one available tool.");

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
    if (job && (job.status === "done" || job.status === "error")) {
      clearInterval(state.pollTimer);
      refreshScanList(jobId);
    }
  }, 1500);
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
  meta.appendChild(el("span", null,
    `${job.target.kind}: ${job.target.display} — status: ${job.status}`));
  if (job.error) meta.appendChild(el("div", "error", job.error));

  renderSummary(job.summary || {});
  renderToolRows(job.results || {});
  populateToolFilter(job.results || {});
  renderFindings();
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
    row.appendChild(el("span", "tstat " + r.status, r.status));
    if (r.status === "ok") {
      row.appendChild(el("span", "thint",
        `${r.summary.total || 0} findings · ${r.duration_ms}ms`));
    } else if (r.status === "unavailable") {
      row.appendChild(el("span", "thint", r.install_hint || ""));
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
