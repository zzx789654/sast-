// Login page. Deliberately separate from app.js: this runs before anyone is
// authenticated, so it should carry as little code as possible.
(function () {
  "use strict";

  const form = document.getElementById("login-form");
  const errorBox = document.getElementById("login-error");

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
})();
