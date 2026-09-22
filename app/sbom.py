"""Package inventory and licences for a scanned project.

Answers two questions the scanners themselves do not: *which* third-party
packages does this project pull in, and *what licence* is each one under.

The distinction that matters, because it decides what this can honestly
report: a lockfile records names and versions, not licences. Trivy reads a
licence from the package's own files, so it only knows one when the package
is actually installed on disk (`node_modules`, `site-packages`, `vendor/`).
A repository checkout usually has a lockfile and no installed packages, so
the normal result is a complete package list with licences unknown -- and
saying "unknown" is the honest answer, not a gap to paper over with a guess
from a package name.
"""
from __future__ import annotations

import json
from pathlib import Path

from .adapters.base import run_command
from .config import config

# How much freedom each licence family leaves you, which is the thing people
# actually need to know. Trivy classifies licences itself; this maps its
# categories onto plain wording and orders them by how much attention they
# deserve. "restricted" is the copyleft group: usable, but with obligations
# that can reach your own source, so it is worth a second look before it
# ships in a product.
CATEGORY_RANK = {
    "forbidden": 0,
    "restricted": 1,
    "reciprocal": 2,
    "notice": 3,
    "permissive": 4,
    "unencumbered": 5,
    "unknown": 6,
}

# Licences that most often need a decision rather than a glance. This is not
# legal advice and is not a blocklist -- it only decides what gets surfaced
# first, so a human looks at the ones that carry obligations.
ATTENTION = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL",
    "GPL-2.0", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "GPL",
    "LGPL-2.1", "LGPL-3.0", "SSPL-1.0", "BUSL-1.1", "Elastic-2.0",
    "CC-BY-NC-4.0", "CC-BY-SA-4.0",
}


def collect(scan_root: Path) -> dict:
    """Build the package inventory. Never raises: this is a report, not a gate."""
    try:
        return _collect(scan_root)
    except Exception as exc:  # noqa: BLE001 - an SBOM must not fail a scan
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}",
                "packages": [], "summary": {}}


def _collect(scan_root: Path) -> dict:
    # --list-all-pkgs is the difference between "packages with a known CVE"
    # and "every package", which is what an inventory has to mean.
    res = run_command(
        ["trivy", "fs", "--format", "json", "--quiet",
         "--list-all-pkgs", "--scanners", "vuln,license", str(scan_root)],
        timeout=config.TOOL_TIMEOUT,
    )
    if res.returncode != 0 and not res.stdout.strip():
        reason = (res.stderr or "").strip().splitlines()
        return {"available": False,
                "reason": reason[-1] if reason else "trivy did not run",
                "packages": [], "summary": {}}

    data = json.loads(res.stdout or "{}")
    out = _parse(data, scan_root)
    if not out["packages"]:
        out["reason"] = _why_empty(scan_root)
        # Trivy needs a pinned version before it will report a package at
        # all, so a requirements.txt of `fastapi>=0.111` yields nothing --
        # not even the names, which are sitting right there in the file.
        # Reading them is worth doing: "which libraries does this pull in"
        # is answerable even when "which exact release" is not.
        declared = read_declared(scan_root)
        if declared:
            out["packages"] = declared
            out["declared_only"] = True
            out["summary"] = _summarise(declared)
    return out


def read_declared(scan_root: Path) -> list[dict]:
    """Package names as the project declares them, with no resolution.

    A deliberately shallow read of the manifests: no transitive
    dependencies, no version resolution, no network. What it produces is
    "the libraries this project asks for", which is a different and smaller
    claim than the inventory trivy builds -- and the UI says so, because a
    list that looks complete but is not is worse than no list.
    """
    seen: dict[tuple, dict] = {}
    try:
        candidates = [p for p in scan_root.rglob("*")
                      if p.name in _DECLARED_READERS and not _vendored(p, scan_root)]
    except OSError:
        return []

    for path in sorted(candidates)[:50]:      # a bound, not a judgement
        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        source = str(path.relative_to(scan_root)).replace("\\", "/")
        for name, spec, ecosystem in _DECLARED_READERS[path.name](text):
            name = name.strip()
            if not name or len(name) > 214:   # npm's own limit; a sanity bound
                continue
            key = (name.lower(), ecosystem)
            if key not in seen:
                seen[key] = {
                    "name": name,
                    # The constraint, not a version: ">=0.111" is honest,
                    # "0.111" would claim we know what is installed.
                    "version": spec.strip(),
                    "ecosystem": ecosystem,
                    "source": source,
                    "licenses": [],
                    "category": "unknown",
                    "direct": True,           # everything here is declared
                    "attention": False,
                }
    return sorted(seen.values(), key=lambda p: p["name"].lower())


def _read_requirements(text: str):
    """pip requirements: one per line, with an optional constraint."""
    import re

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):     # -r, -e, --index-url
            continue
        # name[extras]constraint  ->  name, constraint
        match = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not match:
            continue
        name, _extras, spec = match.groups()
        # A URL or a local path is not a named release.
        if "://" in line or line.startswith("."):
            continue
        yield name, (spec or "").strip(), "pip"


def _read_package_json(text: str):
    """npm manifest: the dependency maps, not the lockfile."""
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    for field in ("dependencies", "devDependencies", "peerDependencies",
                  "optionalDependencies"):
        block = data.get(field)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(name, str) and isinstance(spec, str):
                    yield name, spec, "npm"


def _read_pyproject(text: str):
    """PEP 621 and poetry, without adding a TOML dependency.

    Python 3.11 has tomllib; if the parse fails the file simply contributes
    nothing rather than breaking the scan.
    """
    try:
        import tomllib
    except ImportError:
        return
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001 - a malformed file is not our problem
        return

    import re

    for entry in (data.get("project", {}) or {}).get("dependencies", []) or []:
        if isinstance(entry, str):
            match = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", entry)
            if match:
                yield match.group(1), (match.group(3) or "").strip(), "pip"

    poetry = (((data.get("tool", {}) or {}).get("poetry", {}) or {})
              .get("dependencies", {}) or {})
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            yield name, spec, "pip"
        elif isinstance(spec, dict) and isinstance(spec.get("version"), str):
            yield name, spec["version"], "pip"


def _read_gomod(text: str):
    """go.mod: the require block, or single require lines."""
    import re

    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            parts = line.split()
        elif line.startswith("require "):
            parts = line[len("require "):].split()
        else:
            continue
        if len(parts) >= 2:
            yield parts[0], parts[1], "gomod"


#: Manifests we can read names out of directly. Lockfiles are absent on
#: purpose: when one exists, trivy has already produced a better answer.
_DECLARED_READERS = {
    "requirements.txt": _read_requirements,
    "requirements-dev.txt": _read_requirements,
    "package.json": _read_package_json,
    "pyproject.toml": _read_pyproject,
    "go.mod": _read_gomod,
}


#: Files that declare dependencies, and whether a version can be read from
#: them without resolving anything.
_MANIFESTS = {
    "requirements.txt": "unpinned", "requirements-dev.txt": "unpinned",
    "pyproject.toml": "unpinned", "setup.py": "unpinned",
    "package.json": "unpinned", "Gemfile": "unpinned", "build.gradle": "unpinned",
    "package-lock.json": "locked", "yarn.lock": "locked",
    "pnpm-lock.yaml": "locked", "poetry.lock": "locked",
    "Pipfile.lock": "locked", "go.sum": "locked", "Cargo.lock": "locked",
    "Gemfile.lock": "locked", "composer.lock": "locked", "go.mod": "locked",
}


def _why_empty(scan_root: Path) -> str:
    """Nothing listed. Say whether that means "no dependencies" or "we could
    not read the versions", which are very different answers.

    The common case is a requirements.txt of `package>=1.2` ranges: trivy
    reads pinned versions only, because `>=1.2` does not name a release to
    look up. The project does have dependencies; nothing could be said about
    which ones.
    """
    found: dict[str, str] = {}
    try:
        for path in scan_root.rglob("*"):
            kind = _MANIFESTS.get(path.name)
            if kind and not _vendored(path, scan_root):
                # A lockfile anywhere beats a bare manifest.
                if found.get(path.name) != "locked":
                    found[path.name] = kind
    except OSError:
        return ""

    if not found:
        return "no-manifest"
    if any(kind == "locked" for kind in found.values()):
        # There was something precise to read and still nothing came out.
        return "unreadable:" + ",".join(sorted(found))
    return "unpinned:" + ",".join(sorted(found))


def _vendored(path: Path, root: Path) -> bool:
    parts = set(path.relative_to(root).parts[:-1])
    return bool(parts & {"node_modules", "vendor", ".git", "site-packages",
                         ".venv", "venv", "dist", "build"})


def _parse(data: dict, scan_root: Path) -> dict:
    root = str(scan_root)
    packages: dict[tuple, dict] = {}
    # Licence rows are reported separately from packages, keyed by package
    # name, so they are collected first and joined on afterwards.
    licences: dict[str, list[dict]] = {}

    for result in data.get("Results") or []:
        for row in result.get("Licenses") or []:
            name = row.get("PkgName") or ""
            if not name:
                continue
            licences.setdefault(name, []).append({
                "name": row.get("Name") or "",
                "category": (row.get("Category") or "unknown").lower(),
                "confidence": row.get("Confidence"),
            })

    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        if target.startswith(root):
            target = target[len(root):].lstrip("/\\") or "."
        ecosystem = result.get("Type") or ""

        for pkg in result.get("Packages") or []:
            name = pkg.get("Name") or ""
            version = pkg.get("Version") or ""
            if not name:
                continue
            key = (name, version, ecosystem)
            if key in packages:
                continue

            # Trivy puts a licence on the package when it can read one, and
            # in the separate rows when it scanned the installed files.
            declared = [l for l in (pkg.get("Licenses") or []) if l]
            found = licences.get(name) or []
            names = declared or [l["name"] for l in found if l["name"]]

            packages[key] = {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "source": target,
                "licenses": names,
                "category": _category(names, found),
                "direct": pkg.get("Relationship") == "direct",
                "attention": any(_needs_attention(n) for n in names),
            }

    ordered = sorted(packages.values(),
                     key=lambda p: (not p["attention"],
                                    CATEGORY_RANK.get(p["category"], 6),
                                    p["name"].lower()))
    return {"available": True, "reason": "", "packages": ordered,
            "summary": _summarise(ordered)}


def _category(names: list[str], found: list[dict]) -> str:
    if not names:
        return "unknown"
    # The strictest category wins: one copyleft dependency in a bundle of
    # permissive ones is the fact that matters.
    cats = [f["category"] for f in found if f.get("category")]
    if cats:
        return min(cats, key=lambda c: CATEGORY_RANK.get(c, 6))
    return "restricted" if any(_needs_attention(n) for n in names) else "unknown"


def _needs_attention(name: str) -> bool:
    upper = (name or "").upper()
    return any(a.upper() in upper for a in ATTENTION)


def _summarise(packages: list[dict]) -> dict:
    by_category: dict[str, int] = {}
    by_ecosystem: dict[str, int] = {}
    for pkg in packages:
        by_category[pkg["category"]] = by_category.get(pkg["category"], 0) + 1
        eco = pkg["ecosystem"] or "unknown"
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
    return {
        "total": len(packages),
        "licensed": sum(1 for p in packages if p["licenses"]),
        "unknown": sum(1 for p in packages if not p["licenses"]),
        "attention": sum(1 for p in packages if p["attention"]),
        "by_category": by_category,
        "by_ecosystem": by_ecosystem,
    }
