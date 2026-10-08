"""The front-end's JavaScript as the browser gets it.

Round 49 split app.js into app/static/js/*.js so a scanner with a per-file
time limit can read each one whole. Tests that look for a function or a
string in "the front-end" read all of it, in the order index.html loads it.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "app/static"


def script_files() -> list[Path]:
    html = (STATIC / "index.html").read_text("utf-8")
    return [STATIC / "js" / name for name in re.findall(r'<script src="/js/([^"]+)"', html)]


def frontend_js() -> str:
    return "\n".join(path.read_text("utf-8") for path in script_files())


#: The back end as it was one file (app/main.py) before round 49 split it
#: into the app, shared helpers and one router per area.
BACKEND = ["app/main.py", "app/web.py", "app/routes/accounts.py", "app/routes/mcp_http.py",
           "app/routes/ops.py", "app/routes/scans.py"]


def backend_py() -> str:
    root = STATIC.parents[1]
    return "\n".join((root / rel).read_text("utf-8") for rel in BACKEND)
