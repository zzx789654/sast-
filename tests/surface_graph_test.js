// The attack surface graph model: which boxes and lines the relationship
// graph draws from a scan's attack_surface. Runs the real source.
const fs = require("fs");
const src = (() => {
  // The front-end as index.html loads it (split into static/js/ in round 49).
  const dir = __dirname + "/../app/static/";
  const html = fs.readFileSync(dir + "index.html", "utf8");
  return [...html.matchAll(/<script src="\/js\/([^"]+)"/g)]
    .map((m) => fs.readFileSync(dir + "js/" + m[1], "utf8")).join("\n");
})();
function grab(name) {
  const i = src.indexOf("function " + name + "(");
  return src.slice(i, src.indexOf("\n}\n", i) + 3);
}
const SURFACE_GRAPH_MAX = 60, SURFACE_COL_MAX = 25;
const t = (k, p) => k + (p ? JSON.stringify(p) : "");
const RISKY_HOST = ["private", "metadata", "database"];
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
// Columns: 0 front-end hosts, 1 front-end files, 2 endpoints, 3 back-end files, 4 back-end hosts.
let m = surfaceGraphModel(small);
check(!m.grouped, "small project is not grouped");
check(m.cols[1].map((n) => n.label).sort().join() === "web/a.js,web/cfg.js", "front-end column");
check(m.cols[3].map((n) => n.label).sort().join() === "app/admin.py,app/db.py,app/users.py", "back-end column");
check(m.cols[2][0].e.side === "backend" && m.cols[2][2].e.side === "frontend", "back-end routes first");
const kinds = (a, b) => m.edges.filter(([x, y]) => x.startsWith(a) && y.startsWith(b)).map((e) => e[2]);
check(kinds("f:web/a.js", "e:GET /api/users").join() === "call", "front-end call edge");
check(kinds("e:GET /api/users", "b:app/users.py").join() === "def", "defined-in edge");
check(kinds("f:web/cfg.js", "fh:10.0.0.5").join() === "risk", "front-end to private host is a risk");
check(kinds("b:app/db.py", "bh:mongodb").join() === "conn", "back end to DB is a plain connection");
check(m.cols[0].map((n) => n.label).join() === "10.0.0.5", "front-end host on the front-end side");
check(m.cols[4].map((n) => n.label).join() === "mongodb://u:***@db", "back-end host on the back-end side");
check(m.cols[0][0].risk === true, "risky host flagged");
const rowOf = (col, label) => m.cols[col].find((n) => n.label === label).row;
check(rowOf(0, "10.0.0.5") === rowOf(1, "web/cfg.js"), "host on the same row as its front-end file");
check(rowOf(4, "mongodb://u:***@db") === rowOf(3, "app/db.py"), "host on the same row as its back-end file");

// A host used by front end and back end appears on both sides; a file with
// two hosts takes two rows, so the next file starts below them.
const shared = { endpoints: [], hosts: [
  { host: "api.x.com", category: "third_party", frontend: true, locations: [
    { file: "web/a.js", line: 1, frontend: true }, { file: "srv/b.py", line: 1, frontend: false }] },
  { host: "cdn.y.com", category: "third_party", frontend: true, locations: [{ file: "web/a.js", line: 2, frontend: true }] },
  { host: "z.io", category: "third_party", frontend: true, locations: [{ file: "web/c.js", line: 1, frontend: true }] },
] };
m = surfaceGraphModel(shared);
check(m.cols[0].length === 3 && m.cols[4].length === 1, "shared host drawn once per side");
check(rowOf(1, "web/a.js") === 0.5, "a file with two hosts is centred on them");
check(rowOf(1, "web/c.js") === 2 && rowOf(0, "z.io") === 2, "second file starts after the first file's two hosts");
check(m.rows[0] === 3, "front side is three rows tall");

// Many endpoints: grouped by first path segment, flags carried to the group.
const many = { endpoints: [], hosts: [] };
for (let i = 0; i < 70; i++) many.endpoints.push(ep("GET", "/api/r" + i, "app/a.py"));
many.endpoints.push(ep("POST", "/admin/x", "app/b.py", { flags: ["no_auth_detected"] }));
m = surfaceGraphModel(many);
check(m.grouped, "71 endpoints are grouped");
const groups = Object.fromEntries(m.cols[2].map((n) => [n.group, n]));
check(groups["/api"].count === 70, "api group counts 70");
check(groups["/admin"].flags.has("no_auth_detected"), "group keeps its members' flags");
state.surfaceExpanded.add("/admin");
m = surfaceGraphModel(many);
check(m.cols[2].some((n) => n.e && n.e.path === "/admin/x"), "expanded group shows its endpoints");
state.surfaceExpanded.clear();

// A column with too many files is capped with a "more" box.
const wide = { endpoints: [], hosts: [] };
for (let i = 0; i < 40; i++) wide.endpoints.push(ep("GET", "/p" + i, "f" + i + ".py"));
m = surfaceGraphModel(wide);
check(m.cols[3].length === SURFACE_COL_MAX, "back-end column capped");
check(m.cols[3][SURFACE_COL_MAX - 1].more === true, "last box says how many more");

// Too many hosts on one side: capped too, and hosts of cut files still listed.
const hosty = { endpoints: [], hosts: [] };
for (let i = 0; i < 40; i++) hosty.hosts.push({ host: "h" + i + ".io", category: "third_party",
  frontend: false, locations: [{ file: "s" + i + ".py", line: 1, frontend: false }] });
m = surfaceGraphModel(hosty);
check(m.cols[4].length === SURFACE_COL_MAX && m.cols[4][SURFACE_COL_MAX - 1].more, "host column capped");
check(m.rows[4] >= SURFACE_COL_MAX, "side height covers the capped host column");

if (bad) process.exit(1);
console.log("ALL SURFACE GRAPH CHECKS PASSED");
