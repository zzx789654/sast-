// The formatter's real source against the values that prompted the change.
const fs = require("fs");
const src = fs.readFileSync(__dirname + "/../app/static/app.js", "utf8");
const i = src.indexOf("function elapsed(ms)");
const elapsed = eval("(" + src.slice(i, src.indexOf("\n}", i) + 2) + ")");

const cases = [
  // From the screenshot that prompted this.
  [21438, "21.4s"], [36493, "36.5s"], [2644, "2.6s"], [1055, "1.1s"],
  // Sub-second work is a real measurement, not "0.0s".
  [386, "386ms"], [40, "40ms"], [0, "0ms"], [999, "999ms"],
  [1000, "1.0s"],
  // The minute boundary must not print the same duration two ways.
  [59949, "59.9s"], [59950, "1m 0s"], [60000, "1m 0s"],
  [61500, "1m 2s"], [125000, "2m 5s"], [600000, "10m 0s"],
];

let bad = 0;
for (const [ms, want] of cases) {
  const got = elapsed(ms);
  if (got !== want) { console.error(`FAIL ${ms}ms -> ${got}, expected ${want}`); bad++; }
}
if (bad) process.exit(1);
console.log("ALL ELAPSED CHECKS PASSED");
