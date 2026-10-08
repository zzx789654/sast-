"use strict";
// SAST Studio front-end: The package list and the report around it.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

// ---------------------------------------------------------- package list
// What the project pulls in, and under which licence. Separate from the
// findings because a dependency is not a problem -- it is a fact about the
// project that somebody may still have to approve.
const SBOM_PAGE = 200;

function renderSbom(sbom) {
  const box = $("#sbom-box");
  if (!box) return;
  state.sbom = sbom;

  const packages = sbom.packages || [];
  if (!sbom.available && !packages.length) {
    // Nothing to show, and the reason is usually "no lockfile in here",
    // which the tool rows already say.
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");

  const s = sbom.summary || {};
  // A declared list is a smaller claim than a resolved one -- it is what
  // the project asks for, not what would actually be installed -- so the
  // header says which of the two this is rather than letting a short list
  // look like a complete one.
  $("#sbom-counts").textContent = sbom.declared_only
    ? t("sbom.countsDeclared", { n: s.total || 0 })
    : t("sbom.counts", { n: s.total || 0, unknown: s.unknown || 0 });

  const note = $("#sbom-note");
  const empty = !packages.length;

  // "0 packages" on a project that plainly has dependencies reads as a
  // broken feature. Say which it is: nothing declared, or versions that
  // could not be read.
  if (sbom.declared_only && note) {
    note.textContent = t("sbom.declaredNote");
  } else if (empty && note) {
    note.textContent = emptySbomReason(sbom.reason || "");
  } else if (note) {
    // The honest caveat, stated where it matters: a lockfile has no licence
    // in it, so "unknown" usually means "not installed", not "no licence".
    note.textContent = (s.unknown ? t("sbom.unknownNote") + " " : "")
                       + t("sbom.attentionNote");
  }

  // Controls that do nothing on an empty list.
  ["sbom-filter", "sbom-attention-only", "export-packages"].forEach((id) => {
    const node = $("#" + id);
    if (node) node.disabled = empty;
  });

  renderSbomRows();
}

// The backend says why in a machine-readable form: "no-manifest",
// "unpinned:<files>" or "unreadable:<files>".
function emptySbomReason(reason) {
  const [kind, files] = String(reason).split(":");
  const list = (files || "").split(",").filter(Boolean).join(", ");
  if (kind === "unpinned") {
    return t("sbom.empty.unpinned", { files: list });
  }
  if (kind === "unreadable") {
    return t("sbom.empty.unreadable", { files: list });
  }
  if (kind === "no-manifest") {
    return t("sbom.empty.none");
  }
  return reason || t("sbom.empty.none");
}

function renderSbomRows() {
  const table = $("#sbom-table");
  if (!table) return;
  const packages = ((state.sbom || {}).packages) || [];

  const needle = ($("#sbom-filter") || {}).value || "";
  const onlyAttention = (($("#sbom-attention-only") || {}).checked) || false;
  const shown = packages.filter((p) => {
    if (onlyAttention && !p.attention) return false;
    if (!needle) return true;
    const hay = (p.name + " " + (p.licenses || []).join(" ")).toLowerCase();
    return hay.includes(needle.toLowerCase());
  });

  table.innerHTML = "";
  const head = el("tr");
  ["sbom.package", "sbom.version", "sbom.ecosystem", "sbom.license",
   "sbom.category"].forEach((k) => head.appendChild(el("th", null, t(k))));
  table.appendChild(head);

  shown.slice(0, SBOM_PAGE).forEach((p) => {
    const row = el("tr", p.attention ? "sbom-attention" : null);
    row.appendChild(el("td", "c-name", p.name));
    row.appendChild(el("td", null, p.version || ""));
    row.appendChild(el("td", null, p.ecosystem || ""));

    const lic = el("td");
    if ((p.licenses || []).length) {
      p.licenses.forEach((name) => {
        lic.appendChild(el("span", "lic-tag" + (p.attention ? " warn" : ""), name));
      });
    } else {
      lic.appendChild(el("span", "lic-tag unknown", t("sbom.unknown")));
    }
    row.appendChild(lic);
    row.appendChild(el("td", "matrix-desc", t("sbom.cat." + p.category)));
    table.appendChild(row);
  });

  const more = $("#sbom-more");
  if (more) {
    more.textContent = shown.length > SBOM_PAGE
      ? t("sbom.truncated", { shown: SBOM_PAGE, total: shown.length })
      : t("sbom.showing", { n: shown.length, total: packages.length });
  }
}

function renderConfirmBox(job) {
  const box = $("#confirm-box");
  if (job.status === "policy_review") {
    // The verdict is on the header and in the export. Signing it off happens
    // away from here -- this page has no login, and its history lives in
    // memory, so it was never the right place to record a decision.
    box.classList.add("hidden");
    return;
  }
  if (job.status === "blocked") {
    // Nothing here: the verdict is on the header and every finding is in
    // the filtered list below. Repeating them unfiltered pushed the actual
    // results off the screen on a large scan.
    box.classList.add("hidden");
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

// Scan durations run from a few hundred milliseconds to several minutes, so
// one unit cannot serve the whole range. Milliseconds were exact and unread:
// "36493ms" takes a moment to turn into "half a minute".
function elapsed(ms) {
  if (ms < 1000) {
    // Rounding these to 0.0s would report a real measurement as nothing.
    return Math.round(ms) + "ms";
  }
  const seconds = ms / 1000;
  // Compare the rounded value, or 59999ms prints "60.0s" while 60000ms
  // prints "1m 0s" -- the same duration shown two different ways.
  if (Number(seconds.toFixed(1)) < 60) return seconds.toFixed(1) + "s";
  const mins = Math.floor(seconds / 60);
  const rest = Math.round(seconds - mins * 60);
  // 2m 0s rather than 1m 60s when the remainder rounds up.
  return rest === 60 ? (mins + 1) + "m 0s" : mins + "m " + rest + "s";
}

function renderToolRows(results) {
  const box = $("#tool-results");
  box.innerHTML = "";
  Object.values(results).forEach((r) => {
    const row = el("div", "tool-row");
    row.appendChild(el("span", "tname", r.tool));

    if (r.phase === "running") {
      row.appendChild(el("span", "spinner"));
      // Name the stage rather than just "running": the tools do genuinely
      // different work, and a trivy database download looks identical to a
      // hang if all the UI ever says is "running".
      const key = r.stage ? "stage." + r.stage : "phase.running";
      const label = t(key);
      row.appendChild(el("span", "tstat running",
        label === key ? t("phase.running") : label));
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
      row.appendChild(el("span", "telapsed", elapsed(r.duration_ms || 0)));
    } else if (r.status === "incomplete") {
      // Findings still count; the hint says what they cannot vouch for.
      const skipped = r.skipped || [];
      row.appendChild(el("span", "thint",
        t("tstat.incompleteHint", { n: skipped.length, first: skipped[0] || "" })));
      row.appendChild(el("span", "telapsed", elapsed(r.duration_ms || 0)));
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
  // A big project produces well over a thousand findings, and building that
  // many cards at once locks the page up. Render a page at a time, with a
  // button for the rest, so the first screen is usable immediately.
  // Said once above the list rather than on every card: repeating it on
  // 1343 findings would be its own kind of noise.
  box.appendChild(el("div", "triage-hint", t("triage.hint")));

  const PAGE = 100;
  let shown = 0;
  const more = el("button", "btn ghost show-more");

  function renderPage() {
    const slice = items.slice(shown, shown + PAGE);
    const frag = document.createDocumentFragment();
    slice.forEach((f) => frag.appendChild(renderFinding(f)));
    box.insertBefore(frag, more);
    shown += slice.length;
    more.textContent = t("findings.showMore",
                         { shown: shown, total: items.length });
    more.classList.toggle("hidden", shown >= items.length);
  }

  more.addEventListener("click", renderPage);
  box.appendChild(more);
  renderPage();

  // Printing captures the DOM as it stands, so a paged list would export only
  // the first page. Let the PDF button ask for the rest first.
  renderFindings.renderAll = () => {
    while (shown < items.length) renderPage();
  };
}

// A finding's identity across scans: the same rule in the same place is the
// same finding, even in a later scan of the same project.
function findingKey(f) {
  return [f.tool, f.rule_id, f.file, f.start_line].join("|");
}

// Judgements are recorded on the server, keyed by finding, with the name of
// whoever made the call. They used to live in localStorage, which was the
// right call while they were only notes for the reader -- but a mark now
// changes the scan's verdict, and a judgement that can clear a Critical
// finding has to be attributable and shared, not private to one browser.
let TRIAGE = {};

async function loadTriage() {
  try {
    const res = await fetch("/api/triage");
    if (!res.ok) return;
    TRIAGE = (await res.json()).triage || {};
  } catch (e) { /* the findings still render; they are just unmarked */ }
}

// Returns false when the server refused, so the caller can leave the buttons
// as they were rather than showing a mark that was not recorded.
async function saveTriage(key, verdict, note) {
  const body = new FormData();
  body.append("finding_key", key);
  body.append("verdict", verdict || "");
  if (note) body.append("note", note);
  try {
    const res = await fetch("/api/triage", { method: "POST", body });
    if (!res.ok) return false;
    const data = await res.json();
    if (verdict) TRIAGE[key] = data.mark || { verdict: verdict };
    else delete TRIAGE[key];
    return true;
  } catch (e) {
    return false;
  }
}

function triageVerdict(f) {
  const mark = TRIAGE[findingKey(f)];
  return (mark && mark.verdict) || "";
}

function renderTriage(f) {
  const key = findingKey(f);
  const wrap = el("div", "ftriage");
  const mark = TRIAGE[key] || {};
  const current = mark.verdict || "";
  // A secret keeps counting whatever anyone marks it, so saying otherwise
  // here would be a lie the server then ignores.
  const secret = f.tool === "gitleaks" || (f.extra && f.extra.category === "secret");

  [["", "triage.unset"], ["real", "triage.real"],
   ["false_positive", "triage.falsePositive"],
   ["accepted", "triage.accepted"]].forEach(([value, label]) => {
    const btn = el("button", "tri-btn" + (current === value ? " on" : ""),
                   t(label));
    btn.type = "button";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const ok = await saveTriage(key, value);
      btn.disabled = false;
      if (!ok) return;            // leave the buttons as they were
      renderFindings();
      // The verdict is computed from these marks, so it has to be asked for
      // again -- otherwise the header still shows the old one.
      refreshVerdict();
    });
    wrap.appendChild(btn);
  });

  if (current) {
    // Show the mark itself, so it survives into the printed report.
    const shown = el("span", "tri-mark tri-" + current,
                     t("triage.marked." + current));
    if (mark.marked_by) {
      shown.title = t("triage.by", { who: mark.marked_by,
                                     when: (mark.marked_at || "").slice(0, 16) });
    }
    wrap.appendChild(shown);
    if (secret && current !== "real") {
      // Say why the verdict did not move.
      wrap.appendChild(el("span", "tri-note", t("triage.secretStands")));
    }
  }
  return wrap;
}

async function refreshVerdict() {
  if (!state.selectedJob) return;
  try {
    const res = await fetch(`/api/scans/${state.selectedJob}/reevaluate`,
                            { method: "POST" });
    if (!res.ok) return;
    const evaluation = await res.json();
    if (state.currentJob) {
      state.currentJob.policy_evaluation = evaluation;
      renderJob(state.currentJob);
    }
  } catch (e) { /* the marks are saved; only the badge is stale */ }
}

function renderFinding(f) {
  const judged = triageVerdict(f);
  const card = el("div", "finding " + f.severity
                  + (judged ? " judged judged-" + judged : ""));
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
  // Let the reader record a judgement. The scanner found a pattern; whether
  // it matters here is a human call, and if there is nowhere to write it down
  // the same finding gets re-argued every scan -- and a report full of
  // unexamined noise teaches people to skim past the real ones.
  card.appendChild(renderTriage(f));

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
