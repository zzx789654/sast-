"use strict";
// SAST Studio front-end: The scanner matrix, rulesets, the rule editor and the verdict rule.
// Loaded in order by index.html (core, rules, monitor, scan, report,
// surface); start-up waits for DOMContentLoaded, so order only
// matters for top-level values. Kept small enough for Bearer to analyse
// each file whole (round 49).

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
  if (!AUTH.required) return ["scan", "report", "surface", "monitor", "settings"];
  if (AUTH.user && AUTH.user.is_admin) {
    return ["scan", "report", "surface", "monitor", "settings"];
  }
  // An ordinary account scans and reads its own reports. Monitoring shows the
  // host's containers and Settings manages accounts: neither is theirs.
  // The attack surface is a view of their own reports, so it goes with them.
  return ["scan", "report", "surface", "settings"];
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
    loadTokens(), loadApiPanel(), loadPasswordPolicy(), loadLogs(),
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
