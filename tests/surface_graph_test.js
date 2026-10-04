// The attack surface graph model: which boxes and lines the relationship
// graph draws from a scan's attack_surface. Runs the real source.
const fs = require("fs");
const src = fs.readFileSync(__dirname + "/../app/static/app.js", "utf8");
function grab(name) {
  const i = src.indexOf("function " + name + "(");
  return src.slice(i, src.indexOf("\n}\n", i) + 3);
}
const SURFACE_GRAPH_MAX = 60, SURFACE_COL_MAX = 25;
const t = (k, p) => k + (p ? JSON.stringify(p) : "");
const state = { surfaceExpanded: new Set() };
eval(grab("surfaceGraphModel"));

let bad = 0;
function check(cond, msg) { if (!cond) { console.error("FAIL " + msg); bad++; } }
const ep = (method, path, file, extra) => Object.assign(
  { method, path, file, line: 1, side: "backend", framework: "fastapi", auth: "detected",
    flags: [], called_from: [] }, extra || {});

// Small project: one front-end file calls one route; one front-end file
// connects straight to a private host (a risk); a back end talks to a DB.
const small = {
  endpoints: [
    ep("GET", "/api/users/{id}", "app/users.py", { called_from: [{ file: "web/a.js", line: 2 }] }),
    ep("POST", "/admin/reset", "app/admin.py", { flags: ["no_auth_detected", "unreferenced"] }),
    ep("GET", "/api/x", "web/a.js", { side: "frontend", flags: ["unknown_backend"] }),
  ],
  hosts: [
    { host: "10.0.0.5", category: "private", frontend: true, locations: [{ file: "web/cfg.js", line: 1, frontend: true }] },
    { host: "mongodb://u:***@db", category: "database", frontend: false, locations: [{ file: "app/db.py", line: 3, frontend: false }] },
  ],
};
let m = surfaceGraphModel(small);
check(!m.grouped, "small project is not grouped");
check(m.cols[0].map((n) => n.label).sort().join() === "web/a.js,web/cfg.js", "front-end column");
check(m.cols[2].map((n) => n.label).sort().join() === "app/admin.py,app/db.py,app/users.py", "back-end column");
check(m.cols[1][0].e.side === "backend" && m.cols[1][2].e.side === "frontend", "back-end routes first");
const kinds = (a, b) => m.edges.filter(([x, y]) => x.startsWith(a) && y.startsWith(b)).map((e) => e[2]);
check(kinds("f:web/a.js", "e:GET /api/users").join() === "call", "front-end call edge");
check(kinds("e:GET /api/users", "b:app/users.py").join() === "def", "defined-in edge");
check(kinds("f:web/cfg.js", "h:10.0.0.5").join() === "risk", "front-end to private host is a risk");
check(kinds("b:app/db.py", "h:mongodb").join() === "conn", "back end to DB is a plain connection");
check(m.cols[3].find((n) => n.label === "10.0.0.5").risk === true, "risky host flagged");

// Many endpoints: grouped by first path segment, flags carried to the group.
const many = { endpoints: [], hosts: [] };
for (let i = 0; i < 70; i++) many.endpoints.push(ep("GET", "/api/r" + i, "app/a.py"));
many.endpoints.push(ep("POST", "/admin/x", "app/b.py", { flags: ["no_auth_detected"] }));
m = surfaceGraphModel(many);
check(m.grouped, "71 endpoints are grouped");
const groups = Object.fromEntries(m.cols[1].map((n) => [n.group, n]));
check(groups["/api"].count === 70, "api group counts 70");
check(groups["/admin"].flags.has("no_auth_detected"), "group keeps its members' flags");
state.surfaceExpanded.add("/admin");
m = surfaceGraphModel(many);
check(m.cols[1].some((n) => n.e && n.e.path === "/admin/x"), "expanded group shows its endpoints");
state.surfaceExpanded.clear();

// A column with too many files is capped with a "more" box.
const wide = { endpoints: [], hosts: [] };
for (let i = 0; i < 40; i++) wide.endpoints.push(ep("GET", "/p" + i, "f" + i + ".py"));
m = surfaceGraphModel(wide);
check(m.cols[2].length === SURFACE_COL_MAX, "back-end column capped");
check(m.cols[2][SURFACE_COL_MAX - 1].more === true, "last box says how many more");

if (bad) process.exit(1);
console.log("ALL SURFACE GRAPH CHECKS PASSED");
