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
    return _parse(data, scan_root)


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
