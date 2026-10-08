"use strict";
// SAST Studio front-end: The attack surface.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

// ------------------------------------------------------------ attack surface
// The map of what a project exposes and where it connects, drawn from the
// source alone. Every view of it carries the same caveat: nothing was run, so
// anything decided at run time is missing, and the flags are inferences.
const SURFACE_GRAPH_MAX = 60;   // endpoints drawn one by one before grouping
const SURFACE_COL_MAX = 25;     // files / hosts per graph column
const SVG_NS = "http://www.w3.org/2000/svg";

state.surfaceChart = "graph";
state.surfaceSide = "all";
state.surfaceFlag = null;
state.surfaceQuery = "";
state.surfaceExpanded = new Set();

function svgEl(tag, attrs, parent) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}

function svgText(parent, x, y, s, cls, attrs) {
  const node = svgEl("text", Object.assign({ x, y, class: cls || "" }, attrs || {}), parent);
  node.textContent = s;
  return node;
}

function clip(s, n) {
  s = String(s == null ? "" : s);
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function surfaceOf(job) {
  const surf = (job && job.attack_surface) || {};
  if (state.surfaceShowSamples || !surf.endpoints) return surf;
  // Tests, docs and drafts are full of example addresses and routes. Out of
  // the graph, the mind map and the tables unless asked for; the summary
  // counts from the server already leave them out.
  return {
    ...surf,
    endpoints: surf.endpoints.filter((e) => !e.sample),
    hosts: (surf.hosts || []).filter((h) => !h.sample && !h.mention).map((h) => ({
      ...h, locations: (h.locations || []).filter((l) => !l.sample && !l.mention) })),
  };
}

function surfaceFlagLabel(flag) { return t("surface.flag." + flag); }

// A sentence for the hover: what a value in "Login needed?" or "Notes" means.
function surfaceTip(key) {
  const s = t("surface.tip." + key);
  return s === "surface.tip." + key ? "" : s;
}

function withTip(node, key) {
  const tip = surfaceTip(key);
  if (tip) node.title = tip;
  return node;
}

function renderSurfaceScanSelect() {
  const sel = $("#surface-scan");
  if (!sel) return;
  sel.innerHTML = "";
  (state.jobs || []).forEach((j) => {
    const o = el("option", null,
      shortTarget(j.target.display) + " · " + localTime(j.finished_at || j.created_at));
    o.value = j.id;
    if (j.id === state.selectedJob) o.selected = true;
    sel.appendChild(o);
  });
  sel.disabled = !(state.jobs || []).length;
  $("#surface-export").disabled = !state.selectedJob;
}

function renderSurface(job) {
  const view = $("#view-surface");
  if (!view) return;
  renderSurfaceScanSelect();
  const surf = surfaceOf(job);
  const stateBox = $("#surface-state");
  const body = $("#surface-body");
  const tiles = $("#surface-tiles");
  stateBox.className = "surface-state";
  stateBox.innerHTML = "";
  tiles.innerHTML = "";

  if (!job) {
    stateBox.textContent = t("report.empty");
    body.classList.add("hidden");
    return;
  }
  if (!surf.status) {
    stateBox.textContent = t("surface.pending");
    body.classList.add("hidden");
    return;
  }
  if (surf.status === "error") {
    stateBox.classList.add("bad");
    stateBox.textContent = t("surface.error", { reason: surf.reason || "" });
    body.classList.add("hidden");
    return;
  }
  if (surf.status === "incomplete") {
    stateBox.classList.add("warn");
    stateBox.appendChild(el("strong", null, t("surface.incomplete")));
    stateBox.appendChild(el("div", null, surf.reason || ""));
    if ((surf.skipped || []).length) {
      const det = el("details");
      det.appendChild(el("summary", null, t("surface.skippedList", { n: surf.skipped.length })));
      const ul = el("ul");
      surf.skipped.forEach((s) => ul.appendChild(el("li", null, s)));
      det.appendChild(ul);
      stateBox.appendChild(det);
    }
  } else {
    stateBox.classList.add("hidden");
  }

  const s = surf.summary || {};
  const tileDefs = [
    ["endpoints", s.endpoints, "", null],
    ["noAuth", s.no_auth, "warn", "no_auth_detected"],
    ["unreferenced", s.unreferenced, "warn", "unreferenced"],
    ["unknownBackend", s.unknown_backend, "warn", "unknown_backend"],
    ["hosts", s.hosts, "", "#hosts"],
    ["risks", s.risks, "bad", "#risks"],
  ];
  tileDefs.forEach(([key, n, cls, target]) => {
    const b = el("button", "surface-tile " + (n ? cls : ""));
    b.type = "button";
    b.appendChild(el("div", "n", String(n || 0)));
    b.appendChild(el("div", "l", t("surface.tile." + key)));
    b.addEventListener("click", () => {
      if (target === "#hosts") { $("#surface-hosts-panel").scrollIntoView({ behavior: "smooth" }); return; }
      if (target === "#risks") { $("#surface-risks-panel").scrollIntoView({ behavior: "smooth" }); return; }
      state.surfaceFlag = target;
      renderSurfaceEndpoints(surf);
      $("#surface-endpoints-panel").scrollIntoView({ behavior: "smooth" });
    });
    tiles.appendChild(b);
  });

  const samples = s.samples || {};
  const nSamples = (samples.endpoints || 0) + (samples.hosts || 0) + (samples.mentions || 0);
  $("#surface-samples").classList.toggle("hidden", !nSamples);
  $("#surface-show-samples").checked = !!state.surfaceShowSamples;
  $("#surface-samples-label").textContent = t("surface.showSamples", {
    endpoints: samples.endpoints || 0, hosts: (samples.hosts || 0) + (samples.mentions || 0) });

  body.classList.remove("hidden");
  renderSurfaceChart(job);
  renderSurfaceRisks(surf);
  renderSurfaceEndpoints(surf);
  renderSurfaceHosts(surf);
}

// ---- relationship graph: five columns, mirrored around the endpoints
//   front-end hosts <- front-end files -> endpoints -> back-end files -> back-end hosts
// Each outside host sits on the same row as the program that connects to it,
// so the line from a program to its hosts is short and never crosses the
// middle of the graph.
const RISKY_HOST = ["private", "metadata", "database"];

function surfaceGraphModel(surf) {
  // Endpoints ordered by the file that defines them, so the lines into the
  // back-end column run roughly parallel instead of crossing.
  const eps = (surf.endpoints || []).slice().sort((a, b) =>
    (a.side !== b.side ? (a.side === "backend" ? -1 : 1) : 0) ||
    a.file.localeCompare(b.file) || a.path.localeCompare(b.path));
  const grouped = eps.length > SURFACE_GRAPH_MAX;
  const epNodes = new Map();      // id -> node
  const epOf = (e) => {
    if (!grouped) return "e:" + e.method + " " + e.path + " " + e.file + ":" + e.line;
    const seg = e.path.indexOf("://") > 0 ? e.path.split("/").slice(0, 3).join("/")
      : "/" + (e.path.split("/").filter(Boolean)[0] || "");
    return state.surfaceExpanded.has(seg)
      ? "e:" + e.method + " " + e.path + " " + e.file + ":" + e.line : "g:" + seg;
  };
  const front = new Map(), back = new Map();
  const frontHosts = new Map(), backHosts = new Map();
  const owned = new Map();        // file node id -> its host node ids, first seen first
  const edges = new Set();
  const addEdge = (a, b, kind) => edges.add(a + "\u0000" + b + "\u0000" + kind);

  eps.forEach((e) => {
    const id = epOf(e);
    let node = epNodes.get(id);
    if (!node) {
      node = id.startsWith("g:")
        ? { id, group: id.slice(2), count: 0, flags: new Set(), auth: "detected" }
        : { id, e, flags: new Set(e.flags || []), auth: e.auth };
      epNodes.set(id, node);
    }
    if (node.group != null) {
      node.count++;
      (e.flags || []).forEach((f) => node.flags.add(f));
    }
    if (e.side === "backend") {
      back.set(e.file, { id: "b:" + e.file, label: e.file, sub: e.framework });
      addEdge(id, "b:" + e.file, "def");
      (e.called_from || []).forEach((c) => {
        if (!front.has(c.file)) front.set(c.file, { id: "f:" + c.file, label: c.file });
        addEdge("f:" + c.file, id, "call");
      });
    } else {
      if (!front.has(e.file)) front.set(e.file, { id: "f:" + e.file, label: e.file });
      addEdge("f:" + e.file, id, "call");
    }
  });
  (surf.hosts || []).forEach((h) => {
    (h.locations || []).forEach((loc) => {
      const files = loc.frontend ? front : back;
      const hosts = loc.frontend ? frontHosts : backHosts;
      const fid = (loc.frontend ? "f:" : "b:") + loc.file;
      const hid = (loc.frontend ? "fh:" : "bh:") + h.host;
      if (!files.has(loc.file)) files.set(loc.file, { id: fid, label: loc.file });
      const risky = loc.frontend && RISKY_HOST.includes(h.category);
      if (!hosts.has(h.host)) hosts.set(h.host, { id: hid, label: h.host, cat: h.category, risk: risky });
      const mine = owned.get(fid) || [];
      if (!mine.includes(hid)) { mine.push(hid); owned.set(fid, mine); }
      addEdge(fid, hid, risky ? "risk" : "conn");
    });
  });

  const more = (key, n) => ({ id: "more:" + key, label: t("surface.more", { n }), more: true });
  const cap = (arr, key) => arr.length <= SURFACE_COL_MAX ? arr
    : arr.slice(0, SURFACE_COL_MAX - 1).concat([more(key, arr.length - SURFACE_COL_MAX + 1)]);

  // One side of the graph: each file takes as many rows as it has hosts not
  // already placed by an earlier file, and those hosts take the same rows.
  function side(fileMap, hostMap, key) {
    const files = cap([...fileMap.values()], key + "f");
    const byId = new Map([...hostMap.values()].map((h) => [h.id, h]));
    const placed = [];
    let row = 0;
    files.forEach((f) => {
      const mine = (owned.get(f.id) || []).map((id) => byId.get(id)).filter((h) => h.row == null);
      mine.forEach((h, i) => { h.row = row + i; placed.push(h); });
      const span = Math.max(1, mine.length);
      f.row = row + (span - 1) / 2;       // centred on its hosts
      row += span;
    });
    // Hosts whose program was cut by the column limit go last.
    byId.forEach((h) => { if (h.row == null) { h.row = row++; placed.push(h); } });
    let hosts = placed;
    if (placed.length > SURFACE_COL_MAX) {
      hosts = placed.slice(0, SURFACE_COL_MAX - 1);
      const m = more(key + "h", placed.length - SURFACE_COL_MAX + 1);
      m.row = hosts[hosts.length - 1].row + 1;
      hosts.push(m);
      row = Math.max(m.row + 1, row);
    }
    return { files, hosts, rows: row };
  }
  const f = side(front, frontHosts, "f"), b = side(back, backHosts, "b");
  const endpoints = [...epNodes.values()];
  endpoints.forEach((n, i) => { n.row = i; });
  return {
    grouped,
    cols: [f.hosts, f.files, endpoints, b.files, b.hosts],
    rows: [f.rows, f.rows, endpoints.length, b.rows, b.rows],
    edges: [...edges].map((s) => s.split("\u0000")),
  };
}

function drawSurfaceGraph(surf) {
  const model = surfaceGraphModel(surf);
  const colX = [10, 232, 486, 770, 1012], boxW = [196, 222, 250, 210, 220];
  const rowH = 44, top = 34, boxH = 34;
  const maxRows = Math.max(1, ...model.rows);
  const W = 1242, H = top + maxRows * rowH + 16;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H,
    role: "img", class: "surface-svg", "aria-label": t("surface.graphAria") });
  const heads = ["colFrontHosts", "colFrontend", "colEndpoints", "colBackend", "colBackHosts"];
  const pos = {};
  model.cols.forEach((col, ci) => {
    svgText(svg, colX[ci], 18, t("surface." + heads[ci]) + " (" + col.length + ")", "sf-colhead");
    const offset = (maxRows - model.rows[ci]) * rowH / 2;
    col.forEach((n) => { pos[n.id] = { x: colX[ci], y: top + offset + n.row * rowH, w: boxW[ci], ci }; });
  });
  const edgeG = svgEl("g", {}, svg), nodeG = svgEl("g", {}, svg);
  const edgeEls = [];
  model.edges.forEach(([a, b, kind]) => {
    const A = pos[a], B = pos[b];
    if (!A || !B) return;
    // Front-end hosts sit to the left of their program: leave from its left edge.
    const leftward = B.x < A.x;
    const x1 = leftward ? A.x : A.x + A.w, x2 = leftward ? B.x + B.w : B.x;
    const y1 = A.y + boxH / 2, y2 = B.y + boxH / 2, mx = (x1 + x2) / 2;
    const d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    edgeEls.push({ a, b, p: svgEl("path", { d, class: "sf-edge " + kind }, edgeG) });
  });

  const nodeEls = {};
  model.cols.forEach((col, ci) => col.forEach((n) => {
    const P = pos[n.id];
    let cls = "sf-node", line1 = "", line2 = "", badge = "", tip = "";
    const chars = Math.floor(P.w / 7.2);
    if (ci === 2) {
      const flags = n.flags;
      if (flags.has("no_auth_detected")) cls += " noauth";
      if (flags.has("unknown_backend")) cls += " missing";
      if (flags.has("unreferenced")) cls += " orphan";
      if (n.group != null) {
        cls += " group";
        line1 = clip(n.group + "/…", chars);
        line2 = t("surface.groupCount", { n: n.count });
        tip = t("surface.groupHint");
      } else {
        line1 = clip(n.e.method + "  " + n.e.path, chars);
        line2 = [...flags].filter((f) => f !== "external").map(surfaceFlagLabel).join("・") ||
          (n.e.auth === "detected" ? "✓ " + t("surface.auth.detected")
            : ["global", "public", "admin_in_handler", "user_in_handler"].includes(n.e.auth)
              ? t("surface.auth." + n.e.auth) : n.e.framework);
        tip = n.e.method + " " + n.e.path + "\n" + n.e.file + ":" + n.e.line;
      }
    } else {
      if (n.risk) cls += " risk";
      if (n.more) cls += " more";
      line1 = clip(n.label, chars);
      line2 = n.more ? "" : (ci === 0 || ci === 4) ? t("surface.cat." + n.cat)
        : ci === 1 ? t("surface.side.frontend") : (n.sub || t("surface.side.backend"));
      if (n.risk) badge = t("surface.riskBadge");
      tip = n.label;
    }
    const g = svgEl("g", { class: cls, tabindex: 0 }, nodeG);
    svgEl("title", {}, g).textContent = tip;
    svgEl("rect", { x: P.x, y: P.y, width: P.w, height: boxH, rx: 6 }, g);
    svgText(g, P.x + 8, P.y + 14, line1, "sf-l1");
    svgText(g, P.x + 8, P.y + 27, clip(line2, badge ? chars - 6 : chars), "sf-l2");
    if (badge) svgText(g, P.x + P.w - 8, P.y + 27, badge, "sf-badge", { "text-anchor": "end" });
    nodeEls[n.id] = g;
  }));

  let active = null;
  function focus(id) {
    const node = model.cols[2].find((n) => n.id === id);
    if (node && node.group != null) {          // a group expands in place
      state.surfaceExpanded.add(node.group);
      renderSurfaceChart(state.currentJob);
      return;
    }
    active = active === id ? null : id;
    const keep = new Set([id]);
    edgeEls.forEach((e) => { if (e.a === id || e.b === id) { keep.add(e.a); keep.add(e.b); } });
    for (const k in nodeEls) nodeEls[k].classList.toggle("dim", !!active && !keep.has(k));
    edgeEls.forEach((e) => e.p.classList.toggle("dim", !!active && e.a !== id && e.b !== id));
  }
  for (const k in nodeEls) {
    nodeEls[k].addEventListener("click", () => focus(k));
    nodeEls[k].addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); focus(k); }
    });
  }
  return { svg, grouped: model.grouped };
}

// ---- mind map: project -> category -> group -> item
function surfaceMindTree(job) {
  const surf = surfaceOf(job);
  const eps = surf.endpoints || [];
  const LEAVES = 15, GROUPS = 20;
  const limit = (arr) => arr.length > LEAVES
    ? arr.slice(0, LEAVES - 1).concat([{ label: t("surface.more", { n: arr.length - LEAVES + 1 }) }]) : arr;
  const groupBy = (items, keyFn) => {
    const m = new Map();
    items.forEach((it) => { const k = keyFn(it); if (!m.has(k)) m.set(k, []); m.get(k).push(it); });
    return [...m.entries()].slice(0, GROUPS);
  };
  const epLeaf = (e) => {
    const notes = (e.flags || []).filter((f) => f !== "external").map(surfaceFlagLabel).join("・");
    return { label: e.method + " " + e.path, note: notes,
      cls: (e.flags || []).includes("unknown_backend") ? "missing"
        : (e.flags || []).includes("no_auth_detected") ? "noauth" : "" };
  };
  const backend = eps.filter((e) => e.side === "backend");
  const calls = [];
  backend.forEach((e) => (e.called_from || []).forEach((c) => calls.push({ file: c.file, e })));
  eps.filter((e) => e.side === "frontend").forEach((e) => calls.push({ file: e.file, e }));
  const fileName = (f) => f.split("/").pop();
  return { label: clip(job.target.display.split("/").pop() || job.target.display, 16), kids: [
    { label: t("surface.backendRoutes") + " (" + backend.length + ")", kids:
      groupBy(backend, (e) => "/" + (e.path.split("/").filter(Boolean)[0] || ""))
        .map(([k, v]) => ({ label: k, kids: limit(v.map(epLeaf)) })) },
    { label: t("surface.frontendCalls") + " (" + calls.length + ")", kids:
      groupBy(calls, (c) => c.file).map(([k, v]) => ({ label: fileName(k), kids: limit(v.map((c) => epLeaf(c.e))) })) },
    { label: t("surface.tile.hosts") + " (" + (surf.hosts || []).length + ")", kids:
      groupBy(surf.hosts || [], (h) => h.category).map(([k, v]) => ({ label: t("surface.cat." + k),
        kids: limit(v.map((h) => ({ label: h.host,
          cls: h.frontend && ["private", "metadata", "database"].includes(h.category) ? "risk" : "" }))) })) },
    { label: t("surface.tile.risks") + " (" + (surf.risks || []).length + ")", cls: (surf.risks || []).length ? "risk" : "",
      kids: limit((surf.risks || []).map((r) => ({ label: t("surface.risk." + r.kind) + " " + r.detail,
        note: r.file + ":" + r.line, cls: "risk" }))) },
  ]};
}

function drawSurfaceMind(job, host) {
  const tree = surfaceMindTree(job);
  const leafH = 24, colX = [10, 170, 360, 560];
  let leaves = 0;
  (function count(n) { if (n.kids && n.kids.length) n.kids.forEach(count); else leaves++; })(tree);
  const W = 1100, H = Math.max(80, leaves * leafH + 24);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img",
    class: "surface-svg", "aria-label": t("surface.mindAria") });
  host.textContent = "";
  host.appendChild(svg);           // text widths below need it in the page
  let cursor = 12;
  (function place(n, depth) {
    n.depth = depth;
    if (n.kids && n.kids.length) {
      n.kids.forEach((k) => place(k, depth + 1));
      n.y = (n.kids[0].y + n.kids[n.kids.length - 1].y) / 2;
    } else { n.y = cursor + leafH / 2; cursor += leafH; }
  })(tree, 0);
  const eg = svgEl("g", {}, svg), ng = svgEl("g", {}, svg);
  (function draw(n) {
    const x = colX[n.depth];
    if (n.depth === 0) {
      svgEl("rect", { x, y: n.y - 14, width: 140, height: 28, rx: 14, class: "sf-root" }, ng);
      svgText(ng, x + 70, n.y + 4, n.label, "sf-root-t", { "text-anchor": "middle" });
      n.w = 140;
    } else {
      const node = svgText(ng, x, n.y + 4, n.label,
        "sf-mind d" + n.depth + (n.cls ? " " + n.cls : ""));
      n.w = node.getComputedTextLength ? node.getComputedTextLength() : n.label.length * 7;
      if (n.note) svgText(ng, x + n.w + 10, n.y + 4, n.note, "sf-mind-note" + (n.cls ? " " + n.cls : ""));
    }
    (n.kids || []).forEach((k) => {
      const x1 = x + n.w + 6, x2 = colX[k.depth] - 6, mx = (x1 + x2) / 2;
      svgEl("path", { d: `M${x1},${n.y} C${mx},${n.y} ${mx},${k.y} ${x2},${k.y}`,
        class: "sf-edge" + (k.cls === "risk" ? " risk" : "") }, eg);
      draw(k);
    });
  })(tree);
}

function renderSurfaceChart(job) {
  const host = $("#surface-chart");
  if (!host || !job) return;
  const surf = surfaceOf(job);
  const graph = state.surfaceChart === "graph";
  $("#surface-btn-graph").setAttribute("aria-pressed", String(graph));
  $("#surface-btn-mind").setAttribute("aria-pressed", String(!graph));
  $("#surface-chart-seg").setAttribute("aria-label", t("surface.chartTitle"));
  const legend = $("#surface-legend");
  legend.innerHTML = "";
  const items = graph
    ? [["", "surface.legend.call"], ["def", "surface.legend.def"], ["risk", "surface.legend.risk"],
       ["orphan", "surface.legend.orphan"]]
    : [["", "surface.legend.mind"], ["noauth", "surface.legend.noauth"], ["risk", "surface.legend.riskMind"]];
  items.forEach(([cls, key]) => {
    const span = el("span", "sl-item " + cls);
    span.appendChild(el("i"));
    span.appendChild(document.createTextNode(t(key)));
    legend.appendChild(span);
  });
  if (!(surf.endpoints || []).length && !(surf.hosts || []).length) {
    host.textContent = "";
    host.appendChild(el("p", "mon-note", t("surface.empty")));
    $("#surface-hint").textContent = "";
    return;
  }
  if (graph) {
    const { svg, grouped } = drawSurfaceGraph(surf);
    host.textContent = "";
    host.appendChild(svg);
    $("#surface-hint").textContent = t("surface.hint.graph") + (grouped ? " " + t("surface.grouped") : "");
  } else {
    drawSurfaceMind(job, host);
    $("#surface-hint").textContent = t("surface.hint.mind");
  }
}

function renderSurfaceRisks(surf) {
  const box = $("#surface-risks");
  box.innerHTML = "";
  const risks = surf.risks || [];
  if (!risks.length) { box.appendChild(el("p", "mon-note", t("surface.noRisks"))); return; }
  const table = el("table", "mon-table");
  risks.forEach((r) => {
    const tr = el("tr", "sf-risk-row");
    tr.appendChild(el("td", "sf-risk-kind", t("surface.risk." + r.kind)));
    tr.appendChild(el("td", "mono", r.detail));
    const where = el("td", "mono", r.file + (r.line ? ":" + r.line : ""));
    // Listed, not hidden: a wrong guess about a file must stay visible.
    if (r.sample) where.appendChild(el("span", "sf-flag sample", t("surface.sampleTag")));
    tr.appendChild(where);
    table.appendChild(tr);
  });
  box.appendChild(table);
  box.appendChild(el("p", "mon-subnote", t("surface.frontendHeuristic")));
}

function renderSurfaceEndpoints(surf) {
  const table = $("#surface-endpoints");
  const flagBox = $("#surface-flag-filter");
  const q = state.surfaceQuery.toLowerCase();
  const rows = (surf.endpoints || []).filter((e) =>
    (state.surfaceSide === "all" || e.side === state.surfaceSide) &&
    (!state.surfaceFlag || (e.flags || []).includes(state.surfaceFlag)) &&
    (!q || (e.path + " " + e.file).toLowerCase().includes(q)));

  flagBox.innerHTML = "";
  flagBox.classList.toggle("hidden", !state.surfaceFlag);
  if (state.surfaceFlag) {
    flagBox.appendChild(el("span", null, t("surface.filteredBy", { flag: surfaceFlagLabel(state.surfaceFlag) })));
    const clear = el("button", "linkbtn", t("surface.clearFilter"));
    clear.type = "button";
    clear.addEventListener("click", () => { state.surfaceFlag = null; renderSurfaceEndpoints(surf); });
    flagBox.appendChild(clear);
  }
  document.querySelectorAll("#surface-side button").forEach((b) =>
    b.setAttribute("aria-pressed", String(b.dataset.side === state.surfaceSide)));

  const notes = [];
  if (!surf.has_frontend_calls) notes.push(t("surface.noFrontend"));
  if ((surf.truncated || {}).endpoints) notes.push(t("surface.truncated", { n: surf.truncated.endpoints }));
  $("#surface-endpoints-note").textContent = notes.join(" ");

  table.innerHTML = "";
  const head = el("tr");
  ["method", "path", "side", "framework", "auth", "flags", "location", "calledFrom"].forEach((k) =>
    head.appendChild(withTip(el("th", null, t("surface.th." + k)), "th." + k)));
  table.appendChild(head);
  if (!rows.length) {
    const tr = el("tr");
    const td = el("td", "mon-note", t("surface.noRows"));
    td.colSpan = 8;
    tr.appendChild(td);
    table.appendChild(tr);
    return;
  }
  rows.slice(0, 1000).forEach((e) => {
    const tr = el("tr");
    tr.appendChild(el("td", "mono sf-method", e.method));
    tr.appendChild(el("td", "mono", e.path));
    tr.appendChild(el("td", null, t("surface.side." + e.side)));
    tr.appendChild(el("td", null, e.framework));
    tr.appendChild(withTip(el("td", "sf-auth " + e.auth.replace("/", ""),
      e.auth === "n/a" ? "—" : t("surface.auth." + e.auth)), "auth." + e.auth));
    const ftd = el("td");
    (e.flags || []).forEach((f) =>
      ftd.appendChild(withTip(el("span", "sf-flag " + f, surfaceFlagLabel(f)), "flag." + f)));
    tr.appendChild(ftd);
    const loc = el("td", "mono", e.file + ":" + e.line);
    if (e.sample) loc.appendChild(withTip(el("span", "sf-flag sample", t("surface.sampleTag")), "sample"));
    tr.appendChild(loc);
    const callers = e.called_from || [];
    tr.appendChild(el("td", "mono", callers.length
      ? callers.slice(0, 3).map((c) => c.file + ":" + c.line).join(", ") + (callers.length > 3 ? " …" : "")
      : "—"));
    table.appendChild(tr);
  });
}

function renderSurfaceHosts(surf) {
  const table = $("#surface-hosts");
  table.innerHTML = "";
  const hosts = surf.hosts || [];
  if (!hosts.length) {
    const tr = el("tr");
    tr.appendChild(el("td", "mon-note", t("surface.noHosts")));
    table.appendChild(tr);
    return;
  }
  const head = el("tr");
  ["host", "category", "frontend", "locations"].forEach((k) =>
    head.appendChild(el("th", null, t("surface.th." + k))));
  table.appendChild(head);
  hosts.forEach((h) => {
    const risky = h.frontend && ["private", "metadata", "database"].includes(h.category);
    const tr = el("tr", risky ? "sf-risk-row" : "");
    const name = el("td", "mono", h.host);
    if (h.sample) name.appendChild(withTip(el("span", "sf-flag sample", t("surface.sampleTag")), "sample"));
    else if (h.mention) name.appendChild(withTip(el("span", "sf-flag sample", t("surface.mentionTag")), "mention"));
    tr.appendChild(name);
    tr.appendChild(el("td", null, t("surface.cat." + h.category)));
    tr.appendChild(el("td", null, h.frontend ? t("surface.yes") : "—"));
    const locs = h.locations || [];
    tr.appendChild(el("td", "mono", locs.slice(0, 3).map((l) => l.file + ":" + l.line).join(", ") +
      (h.count > 3 ? " " + t("surface.moreCount", { n: h.count - Math.min(3, locs.length) }) : "")));
    table.appendChild(tr);
  });
}

// The report page's card: the headline, the caveat, the risks. It is what
// the PDF carries, so it must make sense without the tab.
function renderSurfaceCard(job) {
  const card = $("#surface-card");
  if (!card) return;
  const surf = surfaceOf(job);
  if (!surf.status) { card.classList.add("hidden"); return; }
  card.classList.remove("hidden");
  const counts = $("#surface-card-counts");
  counts.innerHTML = "";
  const s = surf.summary || {};
  if (surf.status === "error") {
    counts.appendChild(el("span", "surface-card-err", t("surface.error", { reason: surf.reason || "" })));
  } else {
    [["endpoints", s.endpoints], ["noAuth", s.no_auth], ["unreferenced", s.unreferenced],
     ["hosts", s.hosts], ["risks", s.risks]].forEach(([k, n]) => {
      const c = el("span", "scc");
      c.appendChild(el("b", null, String(n || 0)));
      c.appendChild(document.createTextNode(" " + t("surface.tile." + k)));
      counts.appendChild(c);
    });
    if (surf.status === "incomplete") {
      counts.appendChild(el("span", "scc warn", t("surface.incomplete")));
    }
  }
  const ul = $("#surface-card-risks");
  ul.innerHTML = "";
  (surf.risks || []).slice(0, 10).forEach((r) =>
    ul.appendChild(el("li", null, t("surface.risk." + r.kind) + "：" + r.detail + "（" + r.file + ":" + r.line + "）"
      + (r.sample ? " [" + t("surface.sampleTag") + "]" : ""))));
}

function wireSurface() {
  if (!$("#view-surface")) return;
  $("#surface-scan").addEventListener("change", (ev) => {
    state.selectedJob = ev.target.value;
    state.surfaceExpanded = new Set();
    renderReportList();
    loadJob(state.selectedJob);
  });
  $("#surface-export").addEventListener("click", () => {
    if (!state.selectedJob) return;
    window.location.href = `/api/scans/${state.selectedJob}/attack-surface.json`;
  });
  $("#surface-btn-graph").addEventListener("click", () => {
    state.surfaceChart = "graph"; renderSurfaceChart(state.currentJob);
  });
  $("#surface-btn-mind").addEventListener("click", () => {
    state.surfaceChart = "mind"; renderSurfaceChart(state.currentJob);
  });
  document.querySelectorAll("#surface-side button").forEach((b) =>
    b.addEventListener("click", () => {
      state.surfaceSide = b.dataset.side;
      renderSurfaceEndpoints(surfaceOf(state.currentJob));
    }));
  $("#surface-filter").addEventListener("input", (ev) => {
    state.surfaceQuery = ev.target.value;
    renderSurfaceEndpoints(surfaceOf(state.currentJob));
  });
  $("#surface-show-samples").addEventListener("change", (ev) => {
    state.surfaceShowSamples = ev.target.checked;
    renderSurface(state.currentJob);
  });
  $("#surface-card-open").addEventListener("click", () => showView("surface"));
}
