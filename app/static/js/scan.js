"use strict";
// SAST Studio front-end: Inspecting a project, running a scan, rendering it, and start-up.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

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
  if ($("#opt-full-inventory") && $("#opt-full-inventory").checked) {
    fd.append("full_inventory", "true");
  }
  // Only the rules ticked in the editor panel; an empty object means the
  // scanners run with their default rulesets alone.
  const chosen = selectedRules();
  if (Object.keys(chosen).length) {
    fd.append("custom_rules", JSON.stringify(chosen));
  }
  const sets = selectedRulesets();
  if (Object.keys(sets).length) {
    fd.append("rulesets", JSON.stringify(sets));
  }

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
  renderSurfaceScanSelect();
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
  if (job.policy_evaluation && job.policy_evaluation.decision) {
    const decision = job.policy_evaluation.decision;
    meta.appendChild(el("span", "policy-decision gate-" + decision,
      t("policy.gate", { decision: t("policy.decision." + decision) })));
    // A verdict reached by setting findings aside must not look like one
    // reached by having none.
    const counts = job.policy_evaluation.counts || {};
    if (counts.dismissed) {
      meta.appendChild(el("span", "dismissed-note",
        t("verdict.dismissed", { n: counts.dismissed,
                                 total: counts.total_before_triage })));
    }
    // Why a scan with nothing to show is not a pass: say which tool did not
    // finish, so "review" does not read as a finding nobody can see.
    const gaps = job.policy_evaluation.coverage_gaps || [];
    if (gaps.length) {
      meta.appendChild(el("span", "dismissed-note",
        t("verdict.coverageGaps", { n: gaps.length,
          tools: gaps.map((g) => g.tool + " (" + statusLabel(g.status) + ")").join(", ") })));
    }
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
  renderSbom(job.sbom || {});
  renderSurfaceCard(job);
  if (state.view === "surface") renderSurface(job);
  populateToolFilter(job.results || {});
  renderFindings();
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
    else if (state.sbom) renderSbom(state.sbom);
    if (state.view === "monitor") { renderMonitorTools(); loadMonitorDocker(); }
  };
  $("#lang-toggle").addEventListener("click",
    () => setLang(getLang() === "zh" ? "en" : "zh"));
  setLang(getLang());   // apply static i18n + toggle label
  init();
});
