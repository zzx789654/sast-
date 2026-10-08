"use strict";
// SAST Studio front-end: Switching views, the Monitor tab: scanner upgrades, tools and Docker resources.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

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
  $("#upg-start").addEventListener("click", startUpgrade);
  $("#upg-banner").addEventListener("click", () => showView("monitor"));
  $("#report-refresh").addEventListener("click", () => refreshScanList(state.selectedJob));
  $("#export-csv").addEventListener("click", exportCsv);
  const pkgBtn = $("#export-packages");
  if (pkgBtn) {
    pkgBtn.addEventListener("click", () => {
      if (!state.selectedJob) return;
      window.location.href = `/api/scans/${state.selectedJob}/packages.csv`;
    });
  }
  const sbomFilter = $("#sbom-filter");
  if (sbomFilter) sbomFilter.addEventListener("input", renderSbomRows);
  const sbomOnly = $("#sbom-attention-only");
  if (sbomOnly) sbomOnly.addEventListener("change", renderSbomRows);
  $("#export-pdf").addEventListener("click", () => {
    // Render every finding before printing: the list is paged for speed, and
    // a PDF that silently stopped at the first hundred would be worse than
    // slow -- whoever reads it would not know anything was missing.
    if (renderFindings.renderAll) renderFindings.renderAll();
    window.print();
  });
}

const VIEW_KEY = "sast-view";

function rememberView(view) {
  try { localStorage.setItem(VIEW_KEY, view); } catch (e) { /* private mode */ }
}

function lastView() {
  try { return localStorage.getItem(VIEW_KEY) || "scan"; } catch (e) { return "scan"; }
}

function showView(view) {
  state.view = view;
  rememberView(view);
  document.querySelectorAll(".viewtab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === view));
  $("#view-scan").classList.toggle("hidden", view !== "scan");
  $("#view-report").classList.toggle("hidden", view !== "report");
  $("#view-surface").classList.toggle("hidden", view !== "surface");
  $("#view-monitor").classList.toggle("hidden", view !== "monitor");
  // Settings was missing from this list, so the section stayed hidden and the
  // tab showed an empty page. Every view must be toggled here, not just the
  // ones that existed when this function was written.
  $("#view-settings").classList.toggle("hidden", view !== "settings");
  if (view === "monitor") { renderMonitor(); startMonitorPolling(); }
  else stopMonitorPolling();
  if (view === "settings") renderSettings();
  if (view === "report" || view === "surface") refreshScanList(state.selectedJob);
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
  await loadUpgrade();
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
  // Upgrade progress, but only while one is under way: the endpoint is for
  // administrators, and an idle panel has nothing to refresh.
  clearInterval(state.upgTimer);
  state.upgTimer = setInterval(() => { if (state.upgBusy) loadUpgrade(); }, 5000);
}
function stopMonitorPolling() { clearInterval(state.monTimer); clearInterval(state.upgTimer); }

// ---------------------------------------------------------------- upgrades
// The host checks every morning and prepares a verified candidate on its own.
// This panel shows what it found and did, and can ask for one thing only:
// apply the candidate it prepared. While it switches, the
// service restarts, so a failed poll here is expected, not an error.
const UPG_PHASES = ["checking", "downloading", "building", "verifying",
  "waiting_for_scans", "switching", "done"];
const UPG_BUSY = new Set(UPG_PHASES.slice(0, -1).concat(["queued"]));
const UPG_SEEN_KEY = "sast-upg-seen";

function upgSeen() {
  try { return localStorage.getItem(UPG_SEEN_KEY) || ""; } catch (e) { return ""; }
}
function upgMarkSeen(at) {
  try { if (at) localStorage.setItem(UPG_SEEN_KEY, at); } catch (e) { /* private mode */ }
}

function upgVersions(targets, previous) {
  return Object.entries(targets || {}).map(([tool, v]) =>
    `${tool} ${(previous || {})[tool] || "?"} \u2192 ${v}`).join(", ");
}

function upgEventText(ev) {
  const versions = upgVersions(ev.targets, ev.previous);
  const text = t("upg.ev." + ev.kind, { versions, step: ev.step ? t("upg.phase." + ev.step) : "",
    reason: ev.reason || "" });
  return ev.count > 1 ? text + t("upg.ev.repeat", { n: ev.count }) : text;
}

async function fetchUpgrade() {
  let res;
  try {
    res = await fetch("/api/admin/upgrades", { cache: "no-store" });
  } catch (e) {
    return null;                  // restarting mid-switch; the next poll answers
  }
  if (res.status === 401 || res.status === 403) return { forbidden: true };
  if (!res.ok) return null;
  return res.json();
}

// The header: something to apply, or news since this browser last looked.
async function loadUpgradeBanner() {
  const d = await fetchUpgrade();
  const banner = $("#upg-banner");
  if (!d) return;
  if (d.forbidden || !d.enabled) { banner.classList.add("hidden"); clearInterval(state.upgBannerTimer); return; }
  const st = d.status || {};
  const events = st.events || [];
  const unseen = events.filter((e) => e.at > upgSeen());
  const latest = unseen[unseen.length - 1];
  const cand = st.candidate;
  let text = "";
  if (UPG_BUSY.has(st.phase)) text = t("upg.banner.busy", { phase: t("upg.phase." + st.phase) });
  else if (latest) text = upgEventText(latest);
  else if (cand) text = t("upg.banner.ready", { versions: upgVersions(cand.targets, cand.previous) });
  banner.textContent = text;
  banner.className = "upg-banner" + (text ? "" : " hidden")
    + (latest && /failed/.test(latest.kind) ? " bad" : "");
}

async function loadUpgrade() {
  const panel = $("#upgrade-panel");
  const d = await fetchUpgrade();
  if (!d) return;
  if (d.forbidden) { panel.classList.add("hidden"); return; }
  panel.classList.remove("hidden");
  // ops/ is mounted only into the container, so "enabled" also says how
  // this is deployed -- and which way of updating the hint should name.
  $("#mon-update-hint").textContent = t("mon.updateHint") + " "
    + t(d.enabled ? "mon.updateHintDocker" : "mon.updateHintHost");
  const st = d.status || {};
  state.upgBusy = !!d.pending || UPG_BUSY.has(st.phase);

  const label = $("#upg-state");
  label.textContent = !d.enabled ? t("upg.off")
    : d.upstream_check === false ? t("upg.upstreamOff")
    : d.pending ? t("upg.pending")
    : st.phase ? t("upg.phase." + st.phase) : "";
  label.className = "admin-state" + (state.upgBusy ? " busy"
    : st.phase === "failed" ? " bad" : ["done", "ready"].includes(st.phase) ? " good" : "");

  const cand = st.candidate;
  const card = $("#upg-candidate");
  card.textContent = "";
  card.classList.toggle("hidden", !cand);
  if (cand) {
    card.appendChild(el("strong", null, t("upg.candidate", {
      versions: upgVersions(cand.targets, cand.previous) })));
    const crit = cand.critical || {};
    card.appendChild(el("div", "mon-subnote", t("upg.candidateDetail", {
      built: fmtTime(cand.built_at), expires: fmtTime(cand.expires_at),
      current: crit.current ?? "?", candidate: crit.candidate ?? "?" })));
  }
  $("#upg-start").disabled = !d.enabled || state.upgBusy || !cand;
  $("#upg-start").dataset.candidate = cand ? cand.id : "";
  $("#upg-last").textContent = st.last_check
    ? t("upg.lastCheck", { at: fmtTime(st.last_check) }) : t("upg.neverChecked");

  renderUpgradeTools(st.tools || []);
  renderUpgradeSteps(st);
  renderUpgradeEvents(st.events || []);

  const ov = $("#upg-overrides");
  const rows = Object.entries(st.overrides || {});
  ov.classList.toggle("hidden", !rows.length);
  ov.textContent = rows.length ? t("upg.overrides", {
    list: rows.map(([tool, v]) => `${tool} ${v.local} (repo ${v.repo})`).join(", ") }) : "";

  const log = $("#upg-log");
  log.classList.toggle("hidden", !d.log);
  log.textContent = d.log || "";
  log.scrollTop = log.scrollHeight;

  // Opening the panel is reading the news.
  const events = st.events || [];
  if (events.length) upgMarkSeen(events[events.length - 1].at);
  loadUpgradeBanner();
}

function fmtTime(iso) {
  if (!iso) return "?";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function renderUpgradeTools(tools) {
  const box = $("#upg-tools");
  box.textContent = "";
  tools.forEach((row) => {
    const line = el("div", "upg-row" + (row.eligible ? "" : " upg-off"));
    line.appendChild(el("span", "av-name", row.tool));
    line.appendChild(el("span", "av-have", row.installed || "?"));
    if (row.eligible) {
      line.appendChild(el("span", "av-arrow", "\u2192"));
      line.appendChild(el("span", "av-new", row.eligible));
    } else {
      line.appendChild(el("span", "upg-why", row.reason === "up to date"
        ? t("upg.toolCurrent") : (row.reason || "")));
    }
    box.appendChild(line);
  });
}

function renderUpgradeEvents(events) {
  const list = $("#upg-events");
  list.textContent = "";
  if (!events.length) { list.appendChild(el("li", "mon-note", t("upg.noEvents"))); return; }
  events.slice(-10).reverse().forEach((ev) => {
    const li = el("li", "upg-event " + ev.kind);
    li.appendChild(el("span", "upg-ev-at", fmtTime(ev.at)));
    li.appendChild(el("span", "upg-ev-text", upgEventText(ev)));
    list.appendChild(li);
  });
}

function renderUpgradeSteps(st) {
  const list = $("#upg-steps");
  const result = $("#upg-result");
  list.textContent = "";
  const shown = st.phase && !["idle", "ready"].includes(st.phase);
  list.classList.toggle("hidden", !shown);
  result.classList.toggle("hidden", !shown || UPG_BUSY.has(st.phase));
  if (!shown) return;
  // A check stops after "verifying"; an apply starts at "waiting for scans".
  const steps = st.action === "apply" ? UPG_PHASES.slice(4, -1) : UPG_PHASES.slice(0, 4);
  const at = st.phase === "failed" ? steps.indexOf(st.step) : steps.indexOf(st.phase);
  steps.forEach((phase, i) => {
    const cls = st.phase === "done" || i < at ? "done"
      : i === at ? (st.phase === "failed" ? "failed" : "now") : "";
    list.appendChild(el("li", "upg-step " + cls, t("upg.phase." + phase)));
  });
  if (st.phase === "failed") {
    result.className = "upg-result bad";
    result.textContent = t("upg.failedAt", { step: t("upg.phase." + (st.step || "checking")),
      reason: st.reason || "" });
  } else if (st.phase === "done") {
    result.className = "upg-result " + (st.warning ? "bad" : "good");
    result.textContent = t("upg.doneMsg", { list: upgVersions(st.targets, {}) })
      + (st.warning ? " " + st.warning : "");
  }
}

async function upgradePost(path, body, confirmText) {
  if (confirmText && !confirm(confirmText)) return;
  try {
    const res = await fetch(path, { method: "POST", body });
    const d = await res.json();
    if (!d.started) { alert(d.reason || t("upg.requestFailed")); return; }
  } catch (e) {
    alert(t("upg.requestFailed") + ": " + e.message);
    return;
  }
  loadUpgrade();
}

function startUpgrade() {
  const id = $("#upg-start").dataset.candidate;
  if (!id) return;
  const body = new FormData();
  body.append("candidate", id);
  upgradePost("/api/admin/upgrades/apply", body,
    t("upg.confirmApply", { versions: $("#upg-candidate strong").textContent }));
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
  // Defensive: one unexpected response shape should not stop the rest of the
  // page rendering. A cache bug once returned this object without `config`
  // and took the whole Monitor tab down with it.
  const cfg = state.toolsData.config || {};
  if (cfg.allow_local_path === false) {
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

// ---------------------------------------------------------- docker resources
// Shows the limit, the real usage and the host's total together: a limit on
// its own says nothing, since 2GB is generous or crippling depending on what
// the container uses and what the host has.
//
// It produces a compose fragment rather than applying anything. The app can
// reach /containers/update through the mounted socket, but using it would
// give it write access to every container on the host, and compose would
// overwrite the change on the next deploy.

async function loadDockerLimits() {
  const body = $("#dk-rows");
  if (!body) return;
  let data;
  try {
    data = await (await fetch("/api/docker/limits")).json();
  } catch (e) {
    return;
  }

  const host = $("#dk-host");
  if (host) {
    host.textContent = data.available
      ? t("dk.host").replace("{mem}", data.host_memory_text || "?")
                    .replace("{cpus}", data.host_cpus || "?")
      : (data.reason || t("dk.off"));
  }

  body.innerHTML = "";
  if (!data.available || !(data.containers || []).length) {
    const tr = el("tr");
    const td = el("td", "mon-subnote", data.reason || t("dk.off"));
    td.colSpan = 6;
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  data.containers.forEach((c) => body.appendChild(dockerRow(c)));
}

function dockerRow(c) {
  const tr = el("tr");
  tr.dataset.service = c.service;
  tr.appendChild(el("td", "c-name", c.service));

  // An unset limit is the finding, not an empty cell: the container can
  // exhaust the host rather than only itself.
  const mem = el("td");
  if (c.unlimited_memory) {
    mem.appendChild(el("span", "dk-warn", t("dk.unlimited")));
  } else {
    mem.textContent = c.memory_text;
  }
  tr.appendChild(mem);

  tr.appendChild(el("td", "mon-subnote", c.memory_used_text || "—"));

  const cpu = el("td");
  if (c.unlimited_cpus) {
    cpu.appendChild(el("span", "dk-warn", t("dk.unlimited")));
  } else {
    cpu.textContent = String(c.cpus);
  }
  tr.appendChild(cpu);

  // Pre-filled with what is already set, so leaving a row alone keeps it.
  const memIn = el("input", "dk-in dk-mem");
  memIn.type = "text";
  memIn.placeholder = "2g";
  memIn.value = c.memory_text || "";
  const memCell = el("td");
  memCell.appendChild(memIn);
  tr.appendChild(memCell);

  const cpuIn = el("input", "dk-in dk-cpu");
  cpuIn.type = "text";
  cpuIn.placeholder = "2.0";
  cpuIn.value = c.cpus != null ? String(c.cpus) : "";
  const cpuCell = el("td");
  cpuCell.appendChild(cpuIn);
  tr.appendChild(cpuCell);

  return tr;
}

async function generateComposeFragment() {
  const spec = {};
  document.querySelectorAll("#dk-rows tr[data-service]").forEach((tr) => {
    const mem = tr.querySelector(".dk-mem");
    const cpu = tr.querySelector(".dk-cpu");
    const m = mem && mem.value.trim();
    const c = cpu && cpu.value.trim();
    if (m || c) spec[tr.dataset.service] = { memory: m || "", cpus: c || "" };
  });

  const msg = $("#dk-msg");
  const box = $("#dk-result");
  if (!Object.keys(spec).length) {
    if (msg) msg.textContent = t("dk.nothing");
    if (box) box.classList.add("hidden");
    return;
  }

  const body = new FormData();
  body.append("spec", JSON.stringify(spec));
  const res = await fetch("/api/docker/limits/preview", { method: "POST", body });
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).detail || ""; } catch (e) { detail = ""; }
    if (msg) msg.textContent = detail || t("dk.failed");
    if (box) box.classList.add("hidden");
    return;
  }
  const out = await res.json();
  const pre = $("#dk-fragment");
  if (pre) pre.textContent = out.fragment;
  if (box) box.classList.remove("hidden");
  if (msg) msg.textContent = "";
}

async function copyComposeFragment() {
  const pre = $("#dk-fragment");
  const msg = $("#dk-msg");
  if (!pre || !pre.textContent) return;
  try {
    await navigator.clipboard.writeText(pre.textContent);
    if (msg) msg.textContent = t("dk.copied");
  } catch (e) {
    // Clipboard access needs a secure context; over plain http it throws.
    // Select the text instead so it can still be copied by hand.
    const range = document.createRange();
    range.selectNodeContents(pre);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    if (msg) msg.textContent = t("dk.copyManual");
  }
}
