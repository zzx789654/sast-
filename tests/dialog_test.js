// Exercise askForPassword's real source against a small DOM stub. The point
// is the event wiring -- does submit resolve, does Esc resolve null, does the
// close handler double-resolve -- not to re-test the browser.
const fs = require("fs");

const src = fs.readFileSync(__dirname + "/../app/static/app.js", "utf8");
const start = src.indexOf("function askForPassword(");
const end = src.indexOf("\n}\n", start) + 3;
const fnSrc = src.slice(start, end);

function makeNode(id) {
  return {
    id, value: "", textContent: "", open: false,
    _l: {},
    classList: { add() {}, remove() {} },
    focus() {},
    addEventListener(k, f) { (this._l[k] = this._l[k] || []).push(f); },
    removeEventListener(k, f) {
      this._l[k] = (this._l[k] || []).filter((x) => x !== f);
    },
    fire(k, ev) { (this._l[k] || []).slice().forEach((f) => f(ev || {preventDefault(){}})); },
    showModal() { this.open = true; },
    close() { this.open = false; this.fire("close"); },
  };
}

function scenario(name, drive) {
  const nodes = {};
  ["#pw-dialog", "#pw-dialog-form", "#pw-dialog-input", "#pw-dialog-confirm",
   "#pw-dialog-error", "#pw-dialog-title", "#pw-dialog-hint",
   "#pw-dialog-cancel"].forEach((s) => { nodes[s] = makeNode(s); });

  let resolveCount = 0;
  const $ = (s) => nodes[s];
  const t = (k) => k;
  const prompt = () => "fallback";
  const askForPassword = eval(`(${fnSrc})`);

  const p = askForPassword("admin").then((v) => { resolveCount++; return v; });
  drive(nodes);
  return p.then((v) => ({ name, value: v, resolveCount, nodes }));
}

const checks = [];

// 1. Typing a matching pair resolves with the password.
checks.push(scenario("submit matching", (n) => {
  n["#pw-dialog-input"].value = "Sekret-Password-1!";
  n["#pw-dialog-confirm"].value = "Sekret-Password-1!";
  n["#pw-dialog-form"].fire("submit");
}).then((r) => {
  assert(r.value === "Sekret-Password-1!", "submit should resolve the password, got " + r.value);
  assert(r.resolveCount === 1, "resolved more than once: " + r.resolveCount);
  assert(r.nodes["#pw-dialog-input"].value === "", "password left in the DOM");
  assert(r.nodes["#pw-dialog-confirm"].value === "", "confirm left in the DOM");
  assert(r.nodes["#pw-dialog"].open === false, "dialog left open");
  return "submit matching";
}));

// 2. A mismatch must NOT resolve; it stays open for a correction.
checks.push(new Promise((done) => {
  const nodes = {};
  ["#pw-dialog", "#pw-dialog-form", "#pw-dialog-input", "#pw-dialog-confirm",
   "#pw-dialog-error", "#pw-dialog-title", "#pw-dialog-hint",
   "#pw-dialog-cancel"].forEach((s) => { nodes[s] = makeNode(s); });
  let settled = false;
  const $ = (s) => nodes[s];
  const t = (k) => k;
  const prompt = () => null;
  const askForPassword = eval(`(${fnSrc})`);
  askForPassword("admin").then(() => { settled = true; });

  nodes["#pw-dialog-input"].value = "aaaaaaaaaaaa";
  nodes["#pw-dialog-confirm"].value = "bbbbbbbbbbbb";
  nodes["#pw-dialog-form"].fire("submit");

  setTimeout(() => {
    assert(!settled, "a mismatch resolved the promise instead of asking again");
    assert(nodes["#pw-dialog"].open === true, "dialog closed on a mismatch");
    // Correcting it then works.
    nodes["#pw-dialog-confirm"].value = "aaaaaaaaaaaa";
    nodes["#pw-dialog-form"].fire("submit");
    setTimeout(() => {
      assert(settled, "correcting the mismatch did not resolve");
      done("mismatch reprompts");
    }, 0);
  }, 0);
}));

// 3. Esc resolves null exactly once (the close handler must not double-fire).
checks.push(scenario("escape cancels", (n) => {
  n["#pw-dialog"].fire("cancel");
}).then((r) => {
  assert(r.value === null, "Esc should resolve null, got " + r.value);
  assert(r.resolveCount === 1, "resolved more than once");
  return "escape cancels";
}));

// 4. The cancel button resolves null.
checks.push(scenario("cancel button", (n) => {
  n["#pw-dialog-cancel"].fire("click");
}).then((r) => {
  assert(r.value === null, "cancel should resolve null");
  return "cancel button";
}));

// 5. Listeners are removed, so a second use does not stack handlers.
checks.push(scenario("listeners cleaned up", (n) => {
  n["#pw-dialog-input"].value = "Sekret-Password-1!";
  n["#pw-dialog-confirm"].value = "Sekret-Password-1!";
  n["#pw-dialog-form"].fire("submit");
}).then((r) => {
  const left = Object.keys(r.nodes["#pw-dialog"]._l)
    .reduce((n, k) => n + r.nodes["#pw-dialog"]._l[k].length, 0)
    + r.nodes["#pw-dialog-form"]._l.submit.length;
  assert(left === 0, "listeners left behind: " + left);
  return "listeners cleaned up";
}));

function assert(cond, msg) { if (!cond) { throw new Error(msg); } }

Promise.all(checks).then((names) => {
  names.forEach((n) => console.log("  ok:", n));
  console.log("\nALL DIALOG CHECKS PASSED");
}).catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
