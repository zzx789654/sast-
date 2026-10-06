"""Check, inside an image, that every scanner works -- not merely that it runs.

    python -m app.selfcheck probe    each scanner starts
    python -m app.selfcheck sample   each scanner finds the known problems in
                                     a small generated project

Both exit non-zero on any failure. The build, scripts/deploy.sh and the host
updater use them before an image is allowed to serve.

"probe" catches a scanner that cannot start (semgrep dying on import, round
44). It cannot see one that starts and then quietly reports nothing;
"sample" can. The project is written at run
time rather than kept in the repository, so the repository's own scans do
not trip over a deliberately vulnerable sample, and the fake key gitleaks has
to find is assembled here instead of sitting in a file.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .adapters import get_adapters
from .models import ToolStatus

_APP = '''import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    return subprocess.check_output("ls " + request.args.get("d", "."), shell=True)
'''

_JS = 'fetch("http://10.0.0.5:9200/_search");\n'

# Old enough that every advisory database has entries for them.
_REQUIREMENTS = "django==2.2.0\n"
_PACKAGE = '{"name": "selfcheck", "version": "1.0.0", ' \
           '"dependencies": {"lodash": "4.17.15"}}\n'


def _fake_key() -> str:
    # The shape of an AWS access key id, so gitleaks has something to find.
    return "AKIA" + "QZ7NDF3KXM2PLW4R"


def write_sample(root: Path) -> Path:
    (root / "static").mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(_APP, "utf-8")
    (root / "static" / "main.js").write_text(_JS, "utf-8")
    (root / "requirements.txt").write_text(_REQUIREMENTS, "utf-8")
    (root / "package.json").write_text(_PACKAGE, "utf-8")
    (root / "settings.py").write_text(f'AWS_KEY = "{_fake_key()}"\n', "utf-8")
    return root


def _has_cwe(result, cwe: str) -> bool:
    return any(cwe in " ".join(f.cwe) for f in result.findings)


#: What each scanner must report on the sample. At least one finding for
#: all of them; for semgrep, specifically the command injection, since a
#: ruleset that failed to load can still leave a stray finding behind.
EXPECT = {
    "semgrep": lambda r: _has_cwe(r, "CWE-78"),
}


def check_result(result) -> tuple[bool, str]:
    if result.status != ToolStatus.OK:
        return False, f"status {result.status.value}: {result.error or ''}".strip()
    if not result.findings:
        return False, "found nothing in the sample"
    expect = EXPECT.get(result.tool)
    if expect is not None and not expect(result):
        return False, "missed the expected finding"
    return True, f"{len(result.findings)} findings"


def probe(adapters=None) -> list[tuple[str, bool, str]]:
    rows = []
    for adapter in adapters if adapters is not None else get_adapters():
        ok, version = adapter.probe()
        rows.append((adapter.name, ok, version if ok else "does not start"))
    return rows


def sample(adapters=None, root: "Path | None" = None) -> list[tuple[str, bool, str]]:
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        target = write_sample(Path(root or tmp))
        for adapter in adapters if adapters is not None else get_adapters():
            ok, detail = check_result(adapter.scan(target))
            rows.append((adapter.name, ok, detail))
    return rows


def main(argv: list[str], run=None) -> int:
    commands = {"probe": probe, "sample": sample}
    if len(argv) != 1 or argv[0] not in commands:
        print("usage: python -m app.selfcheck probe|sample", file=sys.stderr)
        return 2
    rows = (run or commands[argv[0]])()
    for name, ok, detail in rows:
        print(f"  {name:<12} {'ok' if ok else 'FAILED':<7} {detail}")
    return 0 if rows and all(ok for _, ok, _ in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
