// Login page. Deliberately separate from app.js: this runs before anyone is
// authenticated, so it should carry as little code as possible.
(function () {
  "use strict";

  const form = document.getElementById("login-form");
  const errorBox = document.getElementById("login-error");
  const noteBox = document.getElementById("login-note");
  const expiredForm = document.getElementById("expired-form");

  const $id = (id) => document.getElementById(id);
  const tr = (key, fallback) =>
    (typeof t === "function" ? t(key) : fallback) || fallback;

  // Why the person is looking at this page, when we put them here.
  const params = new URLSearchParams(window.location.search);
  function note(message) {
    if (!noteBox) return;
    noteBox.textContent = message;
    noteBox.classList.remove("hidden");
  }
  if (params.get("changed")) note(tr("login.afterChange", "Password changed. Sign in again."));
  else if (params.get("expired")) note(tr("login.expiredNote", "This password has expired."));

  // i18n.js sets the document language from the stored preference; reuse it so
  // the login page matches the rest of the UI.
  if (typeof applyStaticI18n === "function") {
    try { applyStaticI18n(); } catch (e) { /* markup defaults are fine */ }
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.classList.add("hidden");

    const body = new FormData();
    body.append("username", document.getElementById("login-user").value);
    body.append("password", document.getElementById("login-pass").value);

    let res;
    try {
      res = await fetch("/api/auth/login", { method: "POST", body });
    } catch (e) {
      showError(e.message);
      return;
    }

    if (res.ok) {
      // Signing in succeeds even when the password has expired -- the gate
      // refuses everything else afterwards. So ask before going anywhere,
      // otherwise the person lands on a page that cannot load.
      let expired = false;
      try {
        const me = await (await fetch("/api/auth/whoami")).json();
        expired = !!(me.user && me.user.password_expired);
      } catch (e) { /* treat an unreadable answer as not expired */ }

      if (expired) {
        showExpiredForm();
        return;
      }
      // Replace rather than assign, so Back does not land on the login form
      // of an already-signed-in session.
      window.location.replace("/");
      return;
    }

    let detail = "";
    try {
      detail = (await res.json()).detail || "";
    } catch (e) { /* a non-JSON error still gets the generic message */ }
    showError(detail || (typeof t === "function" ? t("login.failed")
                                                 : "Sign-in failed"));
    document.getElementById("login-pass").value = "";
    document.getElementById("login-pass").focus();
  });

  // ---------------------------------------------------- expired password
  async function showExpiredForm() {
    if (!expiredForm) return;
    form.classList.add("hidden");
    if (noteBox) noteBox.classList.add("hidden");
    expiredForm.classList.remove("hidden");

    // State the rules here: being refused twice without being told what is
    // wanted is the worst version of this screen.
    try {
      const p = await (await fetch("/api/auth/policy")).json();
      const rules = [tr("policy.minLength", "At least {n} characters")
                       .replace("{n}", p.min_length)];
      if (p.require_upper) rules.push(tr("policy.f.upper", "uppercase"));
      if (p.require_lower) rules.push(tr("policy.f.lower", "lowercase"));
      if (p.require_digit) rules.push(tr("policy.f.digit", "a digit"));
      if (p.require_symbol) rules.push(tr("policy.f.symbol", "a symbol"));
      $id("expired-rules").textContent = rules.join(" \u00b7 ");
    } catch (e) { /* the server states the rule again on refusal */ }

    $id("expired-new").focus();
  }

  if (expiredForm) {
    expiredForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const errBox = $id("expired-error");
      errBox.classList.add("hidden");

      const next = $id("expired-new").value;
      if (next !== $id("expired-confirm").value) {
        errBox.textContent = tr("settings.pwMismatch",
                                "The two passwords do not match");
        errBox.classList.remove("hidden");
        return;
      }

      const body = new FormData();
      body.append("username", $id("login-user").value);
      // The password they just signed in with is still the current one.
      body.append("current", $id("login-pass").value);
      body.append("new_password", next);

      let res;
      try {
        res = await fetch("/api/auth/change-expired", { method: "POST", body });
      } catch (e) {
        errBox.textContent = e.message;
        errBox.classList.remove("hidden");
        return;
      }

      if (res.ok) {
        // The change ended every session for this account, including the one
        // just created, so this is a sign-in and not a redirect to the app.
        window.location.replace("/login?changed=1");
        return;
      }

      let detail = "";
      try { detail = (await res.json()).detail || ""; } catch (e) { /* noop */ }
      errBox.textContent = detail || tr("settings.failed", "That did not work");
      errBox.classList.remove("hidden");
    });
  }
})();
