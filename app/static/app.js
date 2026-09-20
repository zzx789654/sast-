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
  sbom: null,         // package inventory for the shown report
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
    loadPolicies(),
    loadRules(),
    loadRulesets(),
    refreshScanList(),
  ].map((p) => p.catch((e) => {
    // One failing endpoint must not leave the rest of the page empty.
    console.error("startup load failed:", e);
  })));

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
  const logins = $("#logins-refresh");
  if (logins) logins.addEventListener("click", loadLoginHistory);

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

// ------------------------------------------------------------ login history
async function loadLoginHistory() {
  const box = $("#logins-list");
  if (!box) return;
  let data;
  try {
    data = await (await fetch("/api/auth/logins")).json();
  } catch (e) {
    return;
  }
  const scope = $("#logins-scope");
  if (scope) {
    scope.textContent = data.scope === "all"
      ? t("logins.scopeAll") : t("logins.scopeMine");
  }
  box.innerHTML = "";
  if (!(data.events || []).length) {
    box.appendChild(el("div", "mon-subnote", t("logins.none")));
    return;
  }
  data.events.forEach((ev) => {
    const row = el("div", "user-row" + (ev.success ? "" : " login-failed"));
    row.appendChild(el("span", "u-tag " + (ev.success ? "ok-tag" : "off"),
                       t(ev.success ? "logins.ok" : "logins.failed")));
    row.appendChild(el("span", "u-name", ev.username));
    if (ev.source) row.appendChild(el("span", "tk-name", ev.source));
    row.appendChild(el("span", "u-last", (ev.at || "").slice(0, 19).replace("T", " ")));
    box.appendChild(row);
  });
}

// ------------------------------------------------------ scanner matrix
// What each tool looks at, and -- the part that matters before pointing this
// at private code -- whether it talks to the internet and what it sends.
// The network column comes from measuring a real scan, not from the docs.
const TOOL_MATRIX = [
  ["semgrep", "sast", "matrix.looks.code", "matrix.semgrep",
   "rules", "matrix.net.semgrep"],
  ["bearer", "sast", "matrix.looks.code", "matrix.bearer",
   "rules", "matrix.net.bearer"],
  ["trivy", "sca", "matrix.looks.deps", "matrix.trivy",
   "db", "matrix.net.trivy"],
  ["npm_audit", "sca", "matrix.looks.deps", "matrix.npm",
   "query", "matrix.net.npm"],
  ["osv_scanner", "sca", "matrix.looks.deps", "matrix.osv",
   "query", "matrix.net.osv"],
  ["gitleaks", "secret", "matrix.looks.files", "matrix.gitleaks",
   "none", "matrix.net.gitleaks"],
];

function renderToolMatrix() {
  const table = $("#tool-matrix");
  if (!table) return;
  table.innerHTML = "";
  const head = el("tr");
  ["matrix.tool", "matrix.kind", "matrix.looksAt", "matrix.finds",
   "matrix.network"].forEach((k) => head.appendChild(el("th", null, t(k))));
  table.appendChild(head);

  const installed = {};
  ((state.toolsData && state.toolsData.tools) || [])
    .forEach((tl) => { installed[tl.name] = tl.available; });

  TOOL_MATRIX.forEach(([name, kind, looksKey, descKey, netKind, netKey]) => {
    const row = el("tr");
    const nameCell = el("td", "c-name", name);
    if (installed[name] === false) {
      nameCell.appendChild(el("span", "u-tag off", t("notInstalled").trim()));
    }
    row.appendChild(nameCell);
    row.appendChild(el("td", null, kind));
    row.appendChild(el("td", null, t(looksKey)));
    row.appendChild(el("td", "matrix-desc", t(descKey)));

    // The column that matters when the code is private: offline is called
    // out, and everything else says what it sends and where.
    const net = el("td", "matrix-net");
    net.appendChild(el("span", "net-tag net-" + netKind, t("matrix.net." + netKind)));
    net.appendChild(el("div", "matrix-desc", t(netKey)));
    row.appendChild(net);
    table.appendChild(row);
  });
}

// Which tabs this account may use. The server already refuses what it must;
// hiding a tab that only ever returns 403 is about not offering a door that
// does not open, not about the boundary itself.
function visibleViews() {
  if (!AUTH.required) return ["scan", "report", "monitor", "settings"];
  if (AUTH.user && AUTH.user.is_admin) {
    return ["scan", "report", "monitor", "settings"];
  }
  // An ordinary account scans and reads its own reports. Monitoring shows the
  // host's containers and Settings manages accounts: neither is theirs.
  return ["scan", "report", "settings"];
}

function applyRoleVisibility() {
  const allowed = visibleViews();
  document.querySelectorAll(".viewtab").forEach((tab) => {
    const view = tab.dataset.view;
    const show = allowed.includes(view)
                 && (view !== "settings" || AUTH.required);
    tab.classList.toggle("hidden", !show);
  });
  // Restoring a hidden tab would leave the page blank, so fall back.
  if (!allowed.includes(state.view)) showView("scan");
}

async function renderSettings() {
  await loadWhoami();
  // Independent fetches: one slow or failing panel should not hold up the
  // rest of the page.
  await Promise.all([
    loadTokens(), loadApiPanel(), loadPasswordPolicy(), loadLoginHistory(),
  ].map((p) => p.catch(() => {})));
  renderToolMatrix();
  if (AUTH.user && AUTH.user.is_admin) await loadUsers();
}

async function loadUsers() {
  const box = $("#users-list");
  if (!box) return;
  let users;
  try {
    const res = await fetch("/api/users");
    if (!res.ok) {
      // An empty list reads as "there are no users", which is never true and
      // is what the screen showed after a self-reset ended the session.
      if (res.status === 401 || res.status === 403) {
        box.innerHTML = "";
        box.appendChild(el("div", "mon-note", t("settings.sessionEnded")));
      }
      return;
    }
    users = (await res.json()).users || [];
  } catch (e) {
    return;
  }
  box.innerHTML = "";
  users.forEach((u) => box.appendChild(renderUserRow(u)));
}

function renderUserRow(u) {
  const row = el("div", "user-row" + (u.disabled ? " disabled" : ""));
  row.appendChild(el("span", "u-name", u.username));
  if (u.is_admin) row.appendChild(el("span", "u-tag admin", t("settings.adminBadge")));
  if (u.disabled) row.appendChild(el("span", "u-tag off", t("settings.disabled")));
  row.appendChild(el("span", "u-last",
    u.last_login ? t("settings.lastLogin", { when: u.last_login.slice(0, 16) })
                 : t("settings.neverLoggedIn")));

  const actions = el("div", "u-actions");
  const self = AUTH.user && AUTH.user.username === u.username;

  const toggle = el("button", "btn small",
                    u.disabled ? t("settings.enable") : t("settings.disable"));
  toggle.addEventListener("click", () => setUserState(u.id, { disabled: !u.disabled }));
  actions.appendChild(toggle);

  const admin = el("button", "btn small",
                   u.is_admin ? t("settings.dropAdmin") : t("settings.makeAdmin"));
  admin.addEventListener("click", () => setUserState(u.id, { is_admin: !u.is_admin }));
  actions.appendChild(admin);

  const reset = el("button", "btn small", t("settings.resetPw"));
  reset.addEventListener("click", () => resetUserPassword(u));
  actions.appendChild(reset);

  const del = el("button", "btn small ghost", t("settings.delete"));
  del.disabled = self;      // deleting yourself mid-session is never intended
  del.addEventListener("click", () => deleteUser(u));
  actions.appendChild(del);

  row.appendChild(actions);
  return row;
}

async function setUserState(id, changes) {
  const body = new FormData();
  Object.keys(changes).forEach((k) => body.append(k, String(changes[k])));
  await postUsers(`/api/users/${id}/state`, body);
}

async function resetUserPassword(u) {
  // Not prompt(): it renders the password in clear text and offers it to
  // autofill afterwards. Typed twice, because an administrator setting a
  // password they cannot see has no other way to catch a typo.
  const pw = await askForPassword(u.username);
  if (!pw) return;
  const body = new FormData();
  body.append("password", pw);

  // Changing a password ends every session for that account. When it is your
  // own, this session is one of them: the reload that postUsers does next
  // came back 401 and left an empty user list on screen. Say what happened
  // and go to the login page rather than reloading into nothing.
  const self = AUTH.user && AUTH.user.username === u.username;
  const ok = await postUsers(`/api/users/${u.id}/password`, body,
                             self ? t("settings.pwResetSelf") : t("settings.pwReset"),
                             null, { skipReload: self });
  if (ok && self) signOutAfterPasswordChange();
}

// A password change invalidates this session server-side. Clearing the
// cookie explicitly keeps the browser from carrying a dead session to the
// login page, and the short pause is so the message can be read.
function signOutAfterPasswordChange() {
  setTimeout(async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (e) {
      // Already invalid server-side; the redirect is what matters.
    }
    window.location.replace("/login?changed=1");
  }, 1200);
}

// Resolves to the password, or null when cancelled.
function askForPassword(username) {
  const dlg = $("#pw-dialog");
  const form = $("#pw-dialog-form");
  const input = $("#pw-dialog-input");
  const confirmField = $("#pw-dialog-confirm");
  const error = $("#pw-dialog-error");

  // A browser too old for <dialog> still gets a working control rather than
  // a dead button; the clear-text prompt is the lesser evil against nothing.
  if (!dlg || !dlg.showModal) {
    const typed = prompt(t("settings.promptPw", { name: username }));
    return Promise.resolve(typed || null);
  }

  $("#pw-dialog-title").textContent =
    t("settings.promptPwTitle", { name: username });
  $("#pw-dialog-hint").textContent = t("settings.promptPwHint");
  input.value = "";
  confirmField.value = "";
  error.classList.add("hidden");

  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      // Do not leave the password sitting in the DOM after the dialog closes.
      input.value = "";
      confirmField.value = "";
      if (dlg.open) dlg.close();
      resolve(value);
    };

    const onSubmit = (ev) => {
      ev.preventDefault();
      if (input.value !== confirmField.value) {
        error.textContent = t("settings.pwMismatch");
        error.classList.remove("hidden");
        confirmField.focus();
        return;
      }
      finish(input.value);
    };
    const onCancel = () => finish(null);

    function cleanup() {
      form.removeEventListener("submit", onSubmit);
      $("#pw-dialog-cancel").removeEventListener("click", onCancel);
      dlg.removeEventListener("cancel", onCancel);
      dlg.removeEventListener("close", onCancel);
    }

    form.addEventListener("submit", onSubmit);
    $("#pw-dialog-cancel").addEventListener("click", onCancel);
    dlg.addEventListener("cancel", onCancel);   // Esc
    dlg.addEventListener("close", onCancel);    // closed some other way

    dlg.showModal();
    input.focus();
  });
}

async function deleteUser(u) {
  if (!confirm(t("settings.confirmDelete", { name: u.username }))) return;
  await postUsers(`/api/users/${u.id}`, null, t("settings.deleted"), "DELETE");
}

// One place to talk to the user API, so every failure surfaces the server's
// reason -- "cannot remove the last administrator" is worth reading.
async function postUsers(url, body, okMessage, method, opts) {
  const box = $("#users-result");
  try {
    const res = await fetch(url, { method: method || "POST", body: body || undefined });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showUsersResult(false, data.detail || t("settings.failed"));
      return false;
    }
    if (okMessage) showUsersResult(true, okMessage);
    else if (box) box.classList.add("hidden");
    // Skipped when the call just ended this session: the reload would be a
    // 401 and would wipe the list the caller is still looking at.
    if (!(opts && opts.skipReload)) await loadUsers();
    return true;
  } catch (e) {
    showUsersResult(false, e.message);
    return false;
  }
}

function showUsersResult(ok, message) {
  const box = $("#users-result");
  if (!box) return;
  box.textContent = message;
  box.className = "rule-result " + (ok ? "ok" : "bad");
  box.classList.remove("hidden");
}

function wireSettings() {
  const pwForm = $("#pw-form");
  if (pwForm) {
    pwForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = new FormData();
      body.append("current", $("#pw-current").value);
      body.append("new_password", $("#pw-new").value);
      const res = await fetch("/api/auth/password", { method: "POST", body });
      const data = await res.json().catch(() => ({}));
      const box = $("#pw-result");
      box.textContent = res.ok ? t("settings.pwChanged")
                               : (data.detail || t("settings.failed"));
      box.className = "rule-result " + (res.ok ? "ok" : "bad");
      box.classList.remove("hidden");
      if (res.ok) {
        pwForm.reset();
        // Changing a password ends every session, including this one.
        signOutAfterPasswordChange();
      }
    });
  }

  const logout = $("#logout-btn");
  if (logout) {
    logout.addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.replace("/login");
    });
  }

  const refresh = $("#users-refresh");
  if (refresh) refresh.addEventListener("click", loadUsers);

  const newUser = $("#new-user-form");
  if (newUser) {
    newUser.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = new FormData();
      body.append("username", $("#nu-name").value);
      body.append("password", $("#nu-pass").value);
      body.append("is_admin", $("#nu-admin").checked ? "true" : "false");
      if (await postUsers("/api/users", body, t("settings.userAdded"))) {
        newUser.reset();
      }
    });
  }
}

// -------------------------------------------------------------- rulesets
// Semgrep unions every --config it is given, so these are checkboxes rather
// than a dropdown: adding OWASP on top of the default set adds rules instead
// of swapping them.
const RULESET_STATE = { available: [], enabled: {} };

async function loadRulesets() {
  try {
    const d = await (await fetch("/api/rulesets")).json();
    RULESET_STATE.available = d.semgrep || [];
    (d.default || []).forEach((id) => { RULESET_STATE.enabled[id] = true; });
  } catch (e) {
    RULESET_STATE.available = [];
  }
  renderRulesets();
}

function renderRulesets() {
  const box = $("#ruleset-list");
  if (!box) return;
  box.innerHTML = "";
  if (RULESET_STATE.available.length) {
    box.appendChild(el("div", "rule-group-head", t("rules.group.published")));
  }
  RULESET_STATE.available.forEach((rs) => {
    const row = el("label", "ruleset-row");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!RULESET_STATE.enabled[rs.id];
    cb.addEventListener("change", () => {
      RULESET_STATE.enabled[rs.id] = cb.checked;
    });
    row.appendChild(cb);
    row.appendChild(el("span", "rs-id", rs.id));
    const why = t("ruleset.why." + rs.id.replace("p/", ""));
    if (!why.startsWith("ruleset.why.")) {
      row.appendChild(el("span", "rs-why", why));
    }
    box.appendChild(row);
  });
}

function selectedRulesets() {
  const names = Object.keys(RULESET_STATE.enabled)
    .filter((id) => RULESET_STATE.enabled[id]);
  return names.length ? { semgrep: names } : {};
}

// ------------------------------------------------------------ rule editor
// Custom rules are written here and run by the scanner, so the editor's job is
// to make two things obvious: whether a rule compiles, and which rules this
// scan will actually use. Those are different questions -- a saved rule does
// nothing until it is ticked.
const RULE_STATE = { rules: [], current: null, enabled: {} };

async function loadRules() {
  try {
    const data = await (await fetch("/api/rules")).json();
    RULE_STATE.rules = data.rules || [];
  } catch (e) {
    RULE_STATE.rules = [];
  }
  renderRuleSelect();
  renderRuleEnable();
  if (!RULE_STATE.current && RULE_STATE.rules.length) {
    await openRule(RULE_STATE.rules[0].engine, RULE_STATE.rules[0].name);
  }
}

function renderRuleSelect() {
  const sel = $("#rule-select");
  if (!sel) return;
  const keep = sel.value;
  sel.innerHTML = "";
  ["semgrep", "trivy"].forEach((engine) => {
    const group = document.createElement("optgroup");
    group.label = engine + (engine === "semgrep" ? " (YAML)" : " (Rego)");
    RULE_STATE.rules.filter((r) => r.engine === engine).forEach((r) => {
      const opt = new Option(
        r.name + (r.builtin ? "  \u2014 " + t("rules.builtin") : ""),
        engine + "/" + r.name);
      group.appendChild(opt);
    });
    if (group.children.length) sel.appendChild(group);
  });
  if (keep) sel.value = keep;
}

async function openRule(engine, name) {
  try {
    const r = await (await fetch(`/api/rules/${engine}/${encodeURIComponent(name)}`)).json();
    RULE_STATE.current = r;
    $("#rule-editor").value = r.content;
    $("#rule-select").value = engine + "/" + name;
    $("#rule-name").value = r.builtin ? "" : r.name;
    // A built-in is a worked example, not a document: it can be read and
    // copied from, never overwritten.
    $("#rule-editor").readOnly = false;      // editable, but saves elsewhere
    $("#rule-readonly").classList.toggle("hidden", !r.builtin);
    $("#rule-name-wrap").classList.toggle("hidden", !r.builtin);
    $("#rule-delete").disabled = r.builtin;
    hideRuleResult();
  } catch (e) {
    showRuleResult(false, e.message);
  }
}

function newRule() {
  const engine = (RULE_STATE.current && RULE_STATE.current.engine) || "semgrep";
  RULE_STATE.current = { engine, name: "", builtin: false, content: "" };
  $("#rule-editor").value = "";
  $("#rule-name").value = "";
  $("#rule-name-wrap").classList.remove("hidden");
  $("#rule-readonly").classList.add("hidden");
  $("#rule-delete").disabled = true;
  hideRuleResult();
  $("#rule-name").focus();
}

function currentEngine() {
  return (RULE_STATE.current && RULE_STATE.current.engine) || "semgrep";
}

// Ask the scanner to compile the rule without saving it.
async function validateRule() {
  const fd = new FormData();
  fd.append("engine", currentEngine());
  fd.append("content", $("#rule-editor").value);
  setRuleBusy(true);
  try {
    const r = await (await fetch("/api/rules/validate", { method: "POST", body: fd })).json();
    showRuleResult(r.ok, r.message || (r.ok ? t("rules.ok") : t("rules.bad")));
    return r.ok;
  } catch (e) {
    showRuleResult(false, e.message);
    return false;
  } finally {
    setRuleBusy(false);
  }
}

async function saveRule() {
  const cur = RULE_STATE.current || {};
  // Saving a built-in means saving a copy, so a name is required.
  const name = (cur.builtin || !cur.name)
    ? ($("#rule-name").value || "").trim()
    : cur.name;
  if (!name) {
    showRuleResult(false, t("rules.needName"));
    $("#rule-name").focus();
    return;
  }
  const fd = new FormData();
  fd.append("content", $("#rule-editor").value);
  setRuleBusy(true);
  try {
    const res = await fetch(`/api/rules/${currentEngine()}/${encodeURIComponent(name)}`,
                            { method: "POST", body: fd });
    const body = await res.json();
    if (!res.ok) {
      // The server validates before writing, so this is the compile error.
      showRuleResult(false, body.detail || t("rules.bad"));
      return;
    }
    showRuleResult(true, t("rules.saved", { name }));
    await loadRules();
    await openRule(currentEngine(), name);
  } catch (e) {
    showRuleResult(false, e.message);
  } finally {
    setRuleBusy(false);
  }
}

async function deleteRule() {
  const cur = RULE_STATE.current;
  if (!cur || cur.builtin || !cur.name) return;
  if (!confirm(t("rules.confirmDelete", { name: cur.name }))) return;
  try {
    await fetch(`/api/rules/${cur.engine}/${encodeURIComponent(cur.name)}`,
                { method: "DELETE" });
    delete (RULE_STATE.enabled[cur.engine] || {})[cur.name];
    RULE_STATE.current = null;
    await loadRules();
  } catch (e) {
    showRuleResult(false, e.message);
  }
}

// Which rules this scan will use. Separate from the editor on purpose: saving
// a rule and running it are different decisions.
function renderRuleEnable() {
  const box = $("#rule-enable-list");
  if (!box) return;
  box.innerHTML = "";
  box.appendChild(el("div", "rule-group-head", t("rules.group.own")));
  if (!RULE_STATE.rules.length) {
    box.appendChild(el("div", "mon-subnote", t("rules.none")));
    return;
  }
  RULE_STATE.rules.forEach((r) => {
    const row = el("label", "rule-enable-row");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!(RULE_STATE.enabled[r.engine] || {})[r.name];
    cb.addEventListener("change", () => {
      RULE_STATE.enabled[r.engine] = RULE_STATE.enabled[r.engine] || {};
      RULE_STATE.enabled[r.engine][r.name] = cb.checked;
    });
    row.appendChild(cb);
    row.appendChild(el("span", "re-engine", r.engine));
    row.appendChild(el("span", "re-name", r.name));
    if (r.builtin) row.appendChild(el("span", "re-builtin", t("rules.builtin")));
    box.appendChild(row);
  });
}

// {engine: [name, ...]} for the scan request; empty engines are dropped so the
// backend is not asked to look up nothing.
function selectedRules() {
  const out = {};
  Object.keys(RULE_STATE.enabled).forEach((engine) => {
    const names = Object.keys(RULE_STATE.enabled[engine])
      .filter((n) => RULE_STATE.enabled[engine][n]);
    if (names.length) out[engine] = names;
  });
  return out;
}

function setRuleBusy(busy) {
  ["#rule-validate", "#rule-save", "#rule-delete"].forEach((id) => {
    const b = $(id);
    if (b) b.disabled = busy;
  });
  if (!busy && RULE_STATE.current && RULE_STATE.current.builtin) {
    $("#rule-delete").disabled = true;
  }
}

function showRuleResult(ok, message) {
  const box = $("#rule-result");
  if (!box) return;
  box.textContent = message || "";
  box.className = "rule-result " + (ok ? "ok" : "bad");
  box.classList.toggle("hidden", !message);
}

function hideRuleResult() {
  const box = $("#rule-result");
  if (box) box.classList.add("hidden");
}

function wireRuleEditor() {
  const sel = $("#rule-select");
  if (!sel) return;
  sel.addEventListener("change", () => {
    const [engine, ...rest] = sel.value.split("/");
    openRule(engine, rest.join("/"));
  });
  $("#rule-new").addEventListener("click", newRule);
  $("#rule-validate").addEventListener("click", validateRule);
  $("#rule-save").addEventListener("click", saveRule);
  $("#rule-delete").addEventListener("click", deleteRule);
}

// ------------------------------------------------------------ verdict rule
// The rule is fixed, so there is nothing to choose: state it in one line above
// the scan button instead of asking the user to configure it.
async function loadPolicies() {
  const box = $("#verdict-rule");
  if (box) box.textContent = t("verdict.rule");
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
  $("#view-monitor").classList.toggle("hidden", view !== "monitor");
  // Settings was missing from this list, so the section stayed hidden and the
  // tab showed an empty page. Every view must be toggled here, not just the
  // ones that existed when this function was written.
  $("#view-settings").classList.toggle("hidden", view !== "settings");
  if (view === "monitor") { renderMonitor(); startMonitorPolling(); }
  else stopMonitorPolling();
  if (view === "settings") renderSettings();
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

  // Say what the update actually did. Without this the user has to find
  // "Successfully installed" in a wall of pip output to know whether the
  // restart button matters.
  const outcome = $("#admin-outcome");
  if (outcome) {
    const outs = d.outcomes || {};
    const names = Object.keys(outs);
    if (!running && names.length) {
      outcome.innerHTML = "";
      names.forEach((n) => {
        const row = el("div", "admin-outcome-row");
        row.appendChild(el("span", "ao-tool", n));
        row.appendChild(el("span", "ao-" + outs[n], t("admin.outcome." + outs[n])));
        outcome.appendChild(row);
      });
      if (d.restart_required) {
        outcome.appendChild(el("div", "admin-need-restart", t("admin.needRestart")));
      }
      outcome.classList.remove("hidden");
    } else if (running) {
      outcome.classList.add("hidden");
    }
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
  populateToolFilter(job.results || {});
  renderFindings();
}

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
  $("#sbom-counts").textContent =
    t("sbom.counts", { n: s.total || 0, unknown: s.unknown || 0 });

  const note = $("#sbom-note");
  const empty = !packages.length;

  // "0 packages" on a project that plainly has dependencies reads as a
  // broken feature. Say which it is: nothing declared, or versions that
  // could not be read.
  if (empty && note) {
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

// Judgements live in this browser. They are notes for the person reading the
// report, not an audit trail -- the app has no login, so it cannot say who
// marked what, and pretending otherwise would be worse than not storing it.
const TRIAGE = (() => {
  try {
    return JSON.parse(localStorage.getItem("sast-triage") || "{}");
  } catch (e) {
    return {};
  }
})();

function saveTriage() {
  try {
    localStorage.setItem("sast-triage", JSON.stringify(TRIAGE));
  } catch (e) { /* private window, quota: the UI still works */ }
}

function renderTriage(f) {
  const key = findingKey(f);
  const wrap = el("div", "ftriage");
  const current = TRIAGE[key] || "";

  [["", "triage.unset"], ["real", "triage.real"],
   ["false_positive", "triage.falsePositive"],
   ["accepted", "triage.accepted"]].forEach(([value, label]) => {
    const btn = el("button", "tri-btn" + (current === value ? " on" : ""),
                   t(label));
    btn.type = "button";
    btn.addEventListener("click", () => {
      if (value) TRIAGE[key] = value; else delete TRIAGE[key];
      saveTriage();
      renderFindings();
    });
    wrap.appendChild(btn);
  });

  if (current) {
    // Show the mark itself, so it survives into the printed report.
    wrap.appendChild(el("span", "tri-mark tri-" + current,
                        t("triage.marked." + current)));
  }
  return wrap;
}

function renderFinding(f) {
  const judged = TRIAGE[findingKey(f)] || "";
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
