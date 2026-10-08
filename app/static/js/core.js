"use strict";
// SAST Studio front-end: Shared helpers, start-up, accounts, API tokens, the MCP panel, the password policy and the activity log.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

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
  sbom: null,         // package inventory for the shown report
  view: "scan",       // "scan" | "report" | "monitor"
  monTimer: null,
  jobs: [],           // scan history, for the report list
  selectedJob: null,  // id of the report shown on the right
};

const $ = (sel) => document.querySelector(sel);
// The elements the page is built from, each made from a literal name: nothing
// passed to el() can create a <script>, an <iframe> or anything else.
const MAKE = new Map([
  ["b", () => document.createElement("b")],
  ["button", () => document.createElement("button")],
  ["code", () => document.createElement("code")],
  ["details", () => document.createElement("details")],
  ["div", () => document.createElement("div")],
  ["i", () => document.createElement("i")],
  ["input", () => document.createElement("input")],
  ["label", () => document.createElement("label")],
  ["li", () => document.createElement("li")],
  ["option", () => document.createElement("option")],
  ["p", () => document.createElement("p")],
  ["pre", () => document.createElement("pre")],
  ["span", () => document.createElement("span")],
  ["strong", () => document.createElement("strong")],
  ["summary", () => document.createElement("summary")],
  ["table", () => document.createElement("table")],
  ["td", () => document.createElement("td")],
  ["th", () => document.createElement("th")],
  ["tr", () => document.createElement("tr")],
  ["ul", () => document.createElement("ul")],
]);
const el = (tag, cls, text) => {
  const make = MAKE.get(tag);
  if (!make) throw new Error("el(): not an element this page uses: " + tag);
  const e = make();
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
                  not_applicable: "tstat.not_applicable",
                  incomplete: "tstat.incomplete" };
  return known[s] ? t(known[s]) : s;
}

// ---------------------------------------------------------------- init
async function init() {
  wireTabs();
  wireForm();
  wireFilters();
  wireViewNav();
  wireSurface();
  wireRuleEditor();
  wireSettings();
  wireTokens();

  // These five do not depend on each other, so waiting for each in turn made
  // the page sit blank for as long as the slowest one -- /api/tools probes
  // every scanner, which is most of it. Start them together and let each part
  // of the page fill in as its own data lands.
  await Promise.all([
    loadTools(),
    loadWhoami(),
    loadTriage(),
    loadPolicies(),
    loadRules(),
    loadRulesets(),
    refreshScanList(),
  ].map((p) => p.catch(() => {
    // One failing endpoint must not leave the rest of the page empty. Only a
    // fixed note goes to the console: the failed request, with its answer,
    // is in the browser's network tab, and nothing of it is copied here.
    console.error("a start-up request failed; see the network tab");
  })));

  if (AUTH.user && AUTH.user.is_admin) {
    loadUpgradeBanner();
    state.upgBannerTimer = setInterval(loadUpgradeBanner, 60000);
  }

  // Reopen the tab this browser was last on. It waits for the loads above
  // because whoami decides which tabs this account may see, and restoring a
  // tab that is not allowed would land on a hidden panel.
  const wanted = lastView();
  if (wanted !== state.view && visibleViews().includes(wanted)) {
    showView(wanted);
  }
}

// --------------------------------------------------------------- accounts
// The Settings tab only appears when the deployment actually has accounts, so
// a build running without auth does not show a tab that can do nothing.
const AUTH = { required: false, user: null };

async function loadWhoami() {
  try {
    const d = await (await fetch("/api/auth/whoami")).json();
    AUTH.required = !!d.auth_required;
    AUTH.user = d.user || null;
  } catch (e) {
    return;
  }

  applyRoleVisibility();

  const expired = $("#pw-expired");
  if (expired) {
    expired.classList.toggle("hidden",
                             !(AUTH.user && AUTH.user.password_expired));
  }

  const me = $("#me-label");
  if (me && AUTH.user) {
    me.textContent = AUTH.user.username
      + (AUTH.user.is_admin ? " \u2014 " + t("settings.adminBadge") : "");
  }
  const admin = !!(AUTH.user && AUTH.user.is_admin);

  // Only an administrator can see or change other people's accounts.
  const panel = $("#users-panel");
  if (panel) panel.classList.toggle("hidden", !admin);

  // An administrator already has a reset button on their own row in the
  // table above, so the separate change-password form is a second control
  // for the same job. Everyone else has no other way to change a password,
  // so for them it stays.
  const account = $("#account-panel");
  if (account) account.classList.toggle("hidden", admin);
}

// ------------------------------------------------------------- API tokens
// A token lets a script or an MCP client call the API as you. It is shown
// once, at creation: the server keeps only a hash, so there is nothing to
// show later even if someone asks.
async function loadTokens() {
  const box = $("#tokens-list");
  if (!box) return;
  let tokens = [];
  try {
    tokens = (await (await fetch("/api/tokens")).json()).tokens || [];
  } catch (e) {
    return;
  }
  box.innerHTML = "";
  if (!tokens.length) {
    box.appendChild(el("div", "mon-subnote", t("tokens.none")));
    return;
  }
  tokens.forEach((tk) => {
    const row = el("div", "user-row");
    row.appendChild(el("span", "u-name", tk.prefix + "\u2026"));
    row.appendChild(el("span", "tk-name", tk.name));
    // Always shown, including your own: "whose token is this" is the
    // question the binding exists to answer.
    const owner = el("span", "u-tag owner", tk.username);
    if (AUTH.user && tk.username === AUTH.user.username) {
      owner.classList.add("mine");
      owner.title = t("tokens.yours");
    }
    row.appendChild(owner);
    row.appendChild(el("span", "u-last",
      tk.last_used ? t("tokens.lastUsed", { when: tk.last_used.slice(0, 16) })
                   : t("tokens.neverUsed")));
    const actions = el("div", "u-actions");
    const revoke = el("button", "btn small ghost", t("tokens.revoke"));
    revoke.addEventListener("click", async () => {
      if (!confirm(t("tokens.confirmRevoke", { name: tk.name }))) return;
      await fetch("/api/tokens/" + tk.id, { method: "DELETE" });
      loadTokens();
    });
    actions.appendChild(revoke);
    row.appendChild(actions);
    box.appendChild(row);
  });
}

function wireTokens() {
  const form = $("#new-token-form");
  if (form) {
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = new FormData();
      body.append("name", $("#nt-name").value);
      const res = await fetch("/api/tokens", { method: "POST", body });
      const data = await res.json().catch(() => ({}));
      const box = $("#token-secret");
      if (!res.ok) {
        box.textContent = data.detail || t("settings.failed");
        box.className = "rule-result bad";
      } else {
        // The only time this value exists in a readable form.
        box.textContent = t("tokens.created") + "\n\n" + data.token;
        box.className = "rule-result ok";
        form.reset();
      }
      box.classList.remove("hidden");
      loadTokens();
    });
  }
  const refresh = $("#tokens-refresh");
  if (refresh) refresh.addEventListener("click", loadTokens);
  const dl = $("#mcp-download");
  if (dl) dl.addEventListener("click", downloadMcpConfig);
  const env = $("#env-download");
  if (env) env.addEventListener("click", downloadEnvTemplate);
  const logs = $("#logs-refresh");
  if (logs) logs.addEventListener("click", loadLogs);
  const search = $("#log-search");
  if (search) {
    // Debounced, so typing filters as you go without a request per keystroke.
    let timer = null;
    search.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(loadLogs, 250);
    });
  }
  const level = $("#log-level");
  if (level) level.addEventListener("change", loadLogs);
  const saveDays = $("#log-days-save");
  if (saveDays) saveDays.addEventListener("click", saveRetention);
  const dkRefresh = $("#dk-refresh");
  if (dkRefresh) dkRefresh.addEventListener("click", loadDockerLimits);
  const dkGen = $("#dk-generate");
  if (dkGen) dkGen.addEventListener("click", generateComposeFragment);
  const dkCopy = $("#dk-copy");
  if (dkCopy) dkCopy.addEventListener("click", copyComposeFragment);

  document.querySelectorAll("#settings-nav .subtab").forEach((tab) => {
    tab.addEventListener("click", () => showSettingsGroup(tab.dataset.sub));
  });

  const policy = $("#policy-form");
  if (policy) policy.addEventListener("submit", savePolicy);
}

// Settings has four groups; only one is on screen at a time, so a password
// field is never below a full scanner table.
function showSettingsGroup(name) {
  document.querySelectorAll("#settings-nav .subtab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.sub === name);
  });
  document.querySelectorAll("#view-settings .subview").forEach((box) => {
    box.classList.toggle("hidden", box.dataset.sub !== name);
  });
  // Fetch when the tab is opened. Loading it up front would mean an admin
  // query on every page load for a view most visits never reach.
  if (name === "logs") loadLogs();
  if (name === "docker") loadDockerLimits();
}

// ------------------------------------------------------- API and MCP panel
// Shows how to call this deployment rather than describing it in the abstract:
// the host in these snippets is the one the browser is actually on, so they
// can be copied without editing.
let MCP_CONFIG = null;

async function loadApiPanel() {
  try {
    MCP_CONFIG = await (await fetch("/api/mcp/config")).json();
  } catch (e) {
    return;
  }

  const base = MCP_CONFIG.url.replace(/\/mcp$/, "");
  const curl = $("#api-curl");
  if (curl) {
    curl.textContent =
      "# every endpoint takes the same token\n" +
      'curl -H "Authorization: Bearer sast_..." \\\n' +
      `     ${base}/api/tools`;
  }

  const json = $("#mcp-json");
  if (json) json.textContent = JSON.stringify(MCP_CONFIG.config, null, 2);

  const who = $("#token-owner");
  if (who && AUTH.user) {
    who.textContent = t("tokens.createdAs", { name: AUTH.user.username });
  }

  const envBox = $("#env-template");
  if (envBox) envBox.textContent = MCP_CONFIG.env_template || "";

  const tools = $("#mcp-tools");
  if (tools) {
    tools.innerHTML = "";
    (MCP_CONFIG.tools || []).forEach((t) => {
      const row = el("div", "user-row");
      row.appendChild(el("span", "u-name", t.name));
      row.appendChild(el("span", "tk-name", t.description));
      tools.appendChild(row);
    });
  }
}

function downloadMcpConfig() {
  if (!MCP_CONFIG) return;
  // A file rather than a copy button: an MCP client wants this on disk, and
  // the browser will not let a page write to the clipboard everywhere.
  const blob = new Blob([JSON.stringify(MCP_CONFIG.config, null, 2)],
                        { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "sast-studio-mcp.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadEnvTemplate() {
  if (!MCP_CONFIG || !MCP_CONFIG.env_template) return;
  // The token belongs in a file that is not committed, not pasted into a
  // client config that usually is.
  const blob = new Blob([MCP_CONFIG.env_template], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "sast-studio.env";
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------- password policy
async function loadPasswordPolicy() {
  const box = $("#pw-policy");
  if (!box) return;
  let policy;
  try {
    policy = await (await fetch("/api/auth/policy")).json();
  } catch (e) {
    return;
  }
  box.innerHTML = "";
  const rules = [
    t("policy.minLength", { n: policy.min_length }),
    t("policy.common"),
    t("policy.session", { h: policy.session_hours }),
  ].concat(policy.notes || []);
  rules.forEach((line) => {
    const row = el("div", "policy-line");
    row.appendChild(el("span", "policy-dot", "\u2022"));
    row.appendChild(el("span", null, line));
    box.appendChild(row);
  });

  fillPolicyForm(policy);
}

// The rules apply to everyone, so only an administrator may change them. The
// form is hidden otherwise -- the server refuses either way.
function fillPolicyForm(policy) {
  const form = $("#policy-form");
  if (!form) return;
  const admin = !!(AUTH.user && AUTH.user.is_admin);
  form.classList.toggle("hidden", !admin);
  if (!admin) return;

  const num = (id, v) => { const f = $(id); if (f) f.value = v; };
  const chk = (id, v) => { const f = $(id); if (f) f.checked = !!v; };
  num("#po-min", policy.min_length);
  num("#po-history", policy.history_count);
  num("#po-age", policy.max_age_days);
  num("#po-idle", policy.idle_minutes);
  num("#po-attempts", policy.max_attempts);
  num("#po-lockout", policy.lockout_minutes);
  num("#po-token-days", policy.token_days);
  chk("#po-upper", policy.require_upper);
  chk("#po-lower", policy.require_lower);
  chk("#po-digit", policy.require_digit);
  chk("#po-symbol", policy.require_symbol);
  chk("#po-common", policy.reject_common);
}

async function savePolicy(ev) {
  ev.preventDefault();
  const body = new FormData();
  body.append("min_length", $("#po-min").value);
  body.append("history_count", $("#po-history").value);
  body.append("max_age_days", $("#po-age").value);
  body.append("idle_minutes", $("#po-idle").value);
  body.append("max_attempts", $("#po-attempts").value);
  body.append("lockout_minutes", $("#po-lockout").value);
  body.append("token_days", $("#po-token-days").value);
  [["require_upper", "#po-upper"], ["require_lower", "#po-lower"],
   ["require_digit", "#po-digit"], ["require_symbol", "#po-symbol"],
   ["reject_common", "#po-common"]].forEach(([key, sel]) => {
    body.append(key, $(sel).checked ? "true" : "false");
  });

  const res = await fetch("/api/auth/policy", { method: "POST", body });
  const data = await res.json().catch(() => ({}));
  const out = $("#policy-result");
  if (out) {
    out.textContent = res.ok ? t("policy.saved")
                             : (data.detail || t("settings.failed"));
    out.className = "rule-result " + (res.ok ? "ok" : "bad");
    out.classList.remove("hidden");
  }
  // Re-read rather than trusting the form: the server clamps out-of-range
  // values, so what was saved may not be what was typed.
  if (res.ok) loadPasswordPolicy();
}

// -------------------------------------------------------------- activity log
// One table for scans, logins, service state, docker state and API calls.
// They are together because the useful questions cross categories: "what was
// running when it restarted?" cannot be answered from separate lists.

//: Which categories are ticked. Empty means all, which is also the default --
//: arriving at a filtered view you did not set is disorienting.
const logFilter = { cats: new Set(), level: "" };

function logRowsEl() { return $("#log-rows"); }

async function loadLogs() {
  const body = logRowsEl();
  if (!body) return;
  const params = new URLSearchParams();
  if (logFilter.cats.size) params.set("categories", [...logFilter.cats].join(","));
  if (logFilter.level) params.set("level", logFilter.level);
  const search = $("#log-search");
  if (search && search.value.trim()) params.set("text", search.value.trim());

  let data;
  try {
    data = await (await fetch("/api/logs?" + params.toString())).json();
  } catch (e) {
    return;
  }

  const scope = $("#logs-scope");
  if (scope) {
    scope.textContent = data.scope === "all"
      ? t("logs.scopeAll") : t("logs.scopeMine");
  }
  renderLogChips(data);
  renderLogLevels(data);
  renderRetention(data);

  body.innerHTML = "";
  if (!(data.events || []).length) {
    const tr = el("tr");
    const td = el("td", "mon-subnote", t("logs.none"));
    td.colSpan = 7;
    tr.appendChild(td);
    body.appendChild(tr);
  } else {
    data.events.forEach((ev) => body.appendChild(logRow(ev)));
  }

  const count = $("#log-count");
  if (count) {
    // "showing 200 of 4312" rather than just a number, so a truncated view
    // never reads as the whole story.
    count.textContent = (data.total > (data.events || []).length)
      ? t("logs.showing").replace("{n}", (data.events || []).length)
                         .replace("{total}", data.total)
      : t("logs.total").replace("{total}", data.total);
  }
}

function logRow(ev) {
  const tr = el("tr", "log-" + (ev.level || "info"));
  tr.appendChild(el("td", "log-at", (ev.at || "").slice(0, 19).replace("T", " ")));
  const cat = el("td");
  cat.appendChild(el("span", "log-cat log-cat-" + (ev.category || ""),
                     t("logs.cat." + ev.category) || ev.category));
  tr.appendChild(cat);
  tr.appendChild(el("td", "", t("logs.act." + ev.action) || ev.action || ""));
  tr.appendChild(el("td", "log-actor", ev.actor || "—"));
  tr.appendChild(el("td", "log-src", ev.source || "—"));
  tr.appendChild(el("td", "log-target", ev.target || "—"));
  tr.appendChild(el("td", "log-detail", ev.detail || ""));
  return tr;
}

function renderLogChips(data) {
  const box = $("#log-cats");
  if (!box) return;
  box.innerHTML = "";
  // "All" is a chip rather than an unticked state, so clearing the filter is
  // one click from anywhere instead of untangling which ones are on.
  const all = el("button", "log-chip" + (logFilter.cats.size ? "" : " on"),
                 t("logs.all"));
  all.addEventListener("click", () => { logFilter.cats.clear(); loadLogs(); });
  box.appendChild(all);

  (data.categories || []).forEach((c) => {
    const n = (data.counts || {})[c];
    const label = (t("logs.cat." + c) || c) + (n === undefined ? "" : " (" + n + ")");
    const chip = el("button", "log-chip" + (logFilter.cats.has(c) ? " on" : ""), label);
    chip.addEventListener("click", () => {
      if (logFilter.cats.has(c)) logFilter.cats.delete(c);
      else logFilter.cats.add(c);
      loadLogs();
    });
    box.appendChild(chip);
  });
}

function renderLogLevels(data) {
  const sel = $("#log-level");
  if (!sel || sel.dataset.built === "1") return;
  sel.appendChild(new Option(t("logs.anyLevel"), ""));
  (data.levels || []).forEach((lv) => {
    sel.appendChild(new Option(t("logs.level." + lv) || lv, lv));
  });
  sel.dataset.built = "1";
}

function renderRetention(data) {
  const box = $("#log-retention");
  if (!box) return;
  // Only an administrator can change it, so only an administrator sees it.
  if (data.scope !== "all") { box.classList.add("hidden"); return; }
  box.classList.remove("hidden");
  const input = $("#log-days");
  if (input && document.activeElement !== input) {
    input.value = data.retention_days || "";
  }
}

async function saveRetention() {
  const input = $("#log-days");
  if (!input) return;
  const body = new FormData();
  body.append("days", input.value);
  const res = await fetch("/api/logs/retention", { method: "POST", body });
  const note = $("#log-count");
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).detail || ""; } catch (e) { detail = ""; }
    if (note) note.textContent = detail || t("logs.saveFailed");
    return;
  }
  // Rows outside the new window are gone already, so reload rather than
  // leaving deleted rows on screen.
  loadLogs();
}
