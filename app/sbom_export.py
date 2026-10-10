"""The package inventory as a standard SBOM: CycloneDX 1.6 and SPDX 2.3 JSON.

Built from the inventory app/sbom.py already made, not from a second trivy
run: the workspace is gone by the time anyone downloads a file, and the
inventory has three possible sources (trivy, osv-scanner, the manifests
themselves) that all need to come out in the same shape.

What it will not do is claim more than the inventory knows:

* A package listed from a manifest carries a version *constraint*
  (``>=0.111``), not a version. It goes out with no version and the
  constraint as a property, never as ``version: ">=0.111"``.
* A licence that is not a known SPDX identifier goes out by name
  (CycloneDX) or as a ``LicenseRef-`` with its text (SPDX), so a reader's
  tooling does not reject the file for an id that does not exist.
* Completeness is stated: a manifest-only list is marked incomplete, and
  nothing is ever marked complete -- a static read cannot know that.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from . import __version__

TOOL_NAME = "SAST Studio"

#: Fixed namespace so the same scan always yields the same serial number:
#: downloading twice gives the same document, not two "different" SBOMs.
_NS = uuid.UUID("6f1c5f7e-2b1a-4d3e-9a57-3c1d2e5b8a40")

#: Common SPDX licence identifiers. Not the full list -- an id missing from
#: here is still exported, just by name rather than as an id, which every
#: consumer accepts. Putting an unknown string in an id field is what makes
#: schema validation fail.
SPDX_IDS = {
    "0BSD", "AFL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "Apache-1.1", "Apache-2.0", "Artistic-2.0", "BlueOak-1.0.0",
    "BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
    "BSL-1.0", "BUSL-1.1", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-NC-4.0",
    "CC-BY-SA-4.0", "CC0-1.0", "CDDL-1.0", "CDDL-1.1", "EPL-1.0", "EPL-2.0",
    "EUPL-1.2", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0",
    "GPL-3.0-only", "GPL-3.0-or-later", "HPND", "ISC", "LGPL-2.0",
    "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1", "LGPL-2.1-only",
    "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MIT", "MIT-0", "MPL-1.1", "MPL-2.0", "MS-PL", "NCSA", "OFL-1.1",
    "OpenSSL", "PostgreSQL", "PSF-2.0", "Python-2.0", "Ruby", "SSPL-1.0",
    "Unicode-DFS-2016", "Unicode-3.0", "Unlicense", "UPL-1.0", "W3C", "WTFPL",
    "X11", "Zlib", "ZPL-2.1",
}
_SPDX_UPPER = {i.upper(): i for i in SPDX_IDS}
_OPERATORS = {"AND", "OR", "WITH"}

#: Ecosystem names as trivy, osv-scanner and the manifest readers spell them,
#: mapped to the purl type. Only used when the source gave no purl itself.
_PURL_TYPES = {
    "pip": "pypi", "pypi": "pypi", "pipenv": "pypi", "poetry": "pypi",
    "python-pkg": "pypi", "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "node-pkg": "npm", "gomod": "golang", "go": "golang", "gobinary": "golang",
    "cargo": "cargo", "crates.io": "cargo", "rubygems": "gem",
    "bundler": "gem", "gemspec": "gem", "packagist": "composer",
    "composer": "composer", "nuget": "nuget", "maven": "maven", "jar": "maven",
    "pom": "maven", "gradle": "maven", "pub": "pub", "hex": "hex",
}


# ------------------------------------------------------------------ shared

def _packages(job) -> list[dict]:
    return list((job.sbom or {}).get("packages") or [])


def _declared_only(job) -> bool:
    return bool((job.sbom or {}).get("declared_only"))


def _stamp(job) -> str:
    """The scan's time as UTC with a Z, which SPDX requires exactly."""
    raw = job.finished_at or job.created_at or ""
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        when = datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _doc_uuid(job, kind: str) -> uuid.UUID:
    return uuid.uuid5(_NS, f"{kind}:{job.id}")


def make_purl(pkg: dict, with_version: bool = True) -> str:
    """The package URL: the source's own when it gave one, else built.

    Returns "" for an ecosystem we cannot name -- a made-up purl type would
    send a consumer looking in the wrong registry.
    """
    if pkg.get("purl"):
        return pkg["purl"]
    ptype = _PURL_TYPES.get((pkg.get("ecosystem") or "").lower())
    name = (pkg.get("name") or "").strip()
    if not ptype or not name:
        return ""

    namespace = ""
    if ptype == "pypi":
        # PEP 503 normalisation, which the purl spec asks for.
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ptype == "maven" and ":" in name:
        namespace, name = name.split(":", 1)
    elif ptype in ("npm", "golang", "composer") and "/" in name:
        namespace, name = name.rsplit("/", 1)

    path = "/".join(quote(seg, safe="") for seg in namespace.split("/") if seg)
    out = f"pkg:{ptype}/" + (path + "/" if path else "") + quote(name, safe="")
    version = pkg.get("version") or ""
    if with_version and version:
        out += "@" + quote(version, safe="")
    return out


def _is_pinned(job, pkg: dict) -> bool:
    """A version we may state as a version, not a constraint."""
    return not _declared_only(job) and bool(pkg.get("version"))


def _spdx_expression(licenses: list[str]) -> str:
    """A valid SPDX expression for these licences, or "".

    Each entry may itself be an expression ("MIT OR Apache-2.0"). It is used
    only when every operand is a known id; anything else is not ours to
    guess the spelling of.
    """
    parts = []
    for raw in licenses:
        tokens = raw.replace("(", " ( ").replace(")", " ) ").split()
        if not tokens:
            return ""
        fixed = []
        for tok in tokens:
            if tok in ("(", ")") or tok.upper() in _OPERATORS:
                fixed.append(tok.upper() if tok.upper() in _OPERATORS else tok)
            elif tok.upper() in _SPDX_UPPER:
                fixed.append(_SPDX_UPPER[tok.upper()])
            else:
                return ""
        expr = " ".join(fixed).replace("( ", "(").replace(" )", ")")
        parts.append(f"({expr})" if len(tokens) > 1 and len(licenses) > 1 else expr)
    # Several licence entries on one package: all of them apply.
    return " AND ".join(parts)


# --------------------------------------------------------------- CycloneDX

def to_cyclonedx(job) -> dict:
    packages = _packages(job)
    declared = _declared_only(job)
    root_ref = "root-component"

    components, refs_by_trivy_id, used = [], {}, set()
    for pkg in packages:
        pinned = _is_pinned(job, pkg)
        purl = make_purl(pkg, with_version=pinned)
        ref = purl or f"{pkg.get('ecosystem') or 'unknown'}:{pkg.get('name')}" \
                      + (f"@{pkg.get('version')}" if pinned else "")
        base, n = ref, 1
        while ref in used:                    # bom-ref must be unique
            n += 1
            ref = f"{base}#{n}"
        used.add(ref)
        if pkg.get("ref"):
            refs_by_trivy_id[pkg["ref"]] = ref

        comp: dict = {"type": "library", "bom-ref": ref, "name": pkg.get("name", "")}
        if pinned:
            comp["version"] = pkg["version"]
        if purl:
            comp["purl"] = purl
        lic = _cdx_licenses(pkg.get("licenses") or [])
        if lic:
            comp["licenses"] = lic

        props = [{"name": "sast-studio:ecosystem", "value": pkg.get("ecosystem") or "unknown"},
                 {"name": "sast-studio:licence-category", "value": pkg.get("category") or "unknown"}]
        if pkg.get("source"):
            props.append({"name": "sast-studio:declared-in", "value": pkg["source"]})
        if not pinned and pkg.get("version"):
            props.append({"name": "sast-studio:version-constraint", "value": pkg["version"]})
        if pkg.get("attention"):
            props.append({"name": "sast-studio:licence-needs-attention", "value": "true"})
        comp["properties"] = props
        components.append(comp)

    # Dependency graph: trivy's where it gave one, plus the root's direct
    # dependencies. Every component gets an entry (an empty dependsOn says
    # "no known dependencies", which is what the inventory knows).
    dependencies = [{
        "ref": root_ref,
        "dependsOn": [c["bom-ref"] for c, p in zip(components, packages)
                      if p.get("direct")],
    }]
    for comp, pkg in zip(components, packages):
        deps = [refs_by_trivy_id[d] for d in pkg.get("depends_on") or []
                if d in refs_by_trivy_id]
        dependencies.append({"ref": comp["bom-ref"],
                             "dependsOn": sorted(set(deps))})

    meta_props = [{"name": "sast-studio:scan-id", "value": job.id},
                  {"name": "sast-studio:inventory",
                   "value": "declared-only" if declared else "resolved"}]
    if (job.sbom or {}).get("reason"):
        meta_props.append({"name": "sast-studio:inventory-note",
                           "value": job.sbom["reason"]})

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{_doc_uuid(job, 'cdx')}",
        "version": 1,
        "metadata": {
            "timestamp": _stamp(job),
            "tools": {"components": [{
                "type": "application", "name": TOOL_NAME, "version": __version__}]},
            "component": {"type": "application", "bom-ref": root_ref,
                          "name": job.target.display or job.id},
            "properties": meta_props,
        },
        "components": components,
        "dependencies": dependencies,
        # Never "complete": a static read of a checkout cannot know that.
        "compositions": [{
            "aggregate": "incomplete" if declared else "unknown",
            "assemblies": [root_ref],
        }],
    }


def _cdx_licenses(licenses: list[str]) -> list[dict]:
    if not licenses:
        return []
    expr = _spdx_expression(licenses)
    if expr and (len(licenses) > 1 or any(op in expr.split() for op in _OPERATORS)):
        # CycloneDX allows one expression, alone, in the array.
        return [{"expression": expr}]
    out = []
    for name in licenses:
        known = _SPDX_UPPER.get(name.strip().upper())
        out.append({"license": {"id": known} if known else {"name": name}})
    return out


# -------------------------------------------------------------------- SPDX

def to_spdx(job) -> dict:
    packages = _packages(job)
    declared = _declared_only(job)
    root_id = "SPDXRef-RootPackage"

    spdx_pkgs = [{
        "SPDXID": root_id,
        "name": job.target.display or job.id,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    }]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT",
                      "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": root_id}]
    extracted: dict[str, dict] = {}
    ids_by_trivy_id: dict[str, str] = {}

    for n, pkg in enumerate(packages, start=1):
        sid = f"SPDXRef-Package-{n}"
        if pkg.get("ref"):
            ids_by_trivy_id[pkg["ref"]] = sid
        pinned = _is_pinned(job, pkg)
        entry: dict = {
            "SPDXID": sid,
            "name": pkg.get("name", ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            # Concluded would be a legal judgement; this tool makes none.
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_declared(pkg.get("licenses") or [], extracted),
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        }
        if pinned:
            entry["versionInfo"] = pkg["version"]
        purl = make_purl(pkg, with_version=pinned)
        if purl:
            entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                      "referenceType": "purl",
                                      "referenceLocator": purl}]
        notes = [f"ecosystem: {pkg.get('ecosystem') or 'unknown'}"]
        if pkg.get("source"):
            notes.append(f"declared in: {pkg['source']}")
        if not pinned and pkg.get("version"):
            notes.append(f"version constraint (not a resolved version): {pkg['version']}")
        entry["comment"] = "; ".join(notes)
        spdx_pkgs.append(entry)
        if pkg.get("direct"):
            relationships.append({"spdxElementId": root_id,
                                  "relationshipType": "DEPENDS_ON",
                                  "relatedSpdxElement": sid})

    for n, pkg in enumerate(packages, start=1):
        for dep in sorted(set(pkg.get("depends_on") or [])):
            if dep in ids_by_trivy_id:
                relationships.append({"spdxElementId": f"SPDXRef-Package-{n}",
                                      "relationshipType": "DEPENDS_ON",
                                      "relatedSpdxElement": ids_by_trivy_id[dep]})

    doc: dict = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sast-studio-{job.id}",
        # A unique URI, not a location: nothing is served there.
        "documentNamespace": f"https://spdx.org/spdxdocs/sast-studio-{job.id}-{_doc_uuid(job, 'spdx')}",
        "creationInfo": {
            "created": _stamp(job),
            "creators": [f"Tool: {TOOL_NAME}-{__version__}"],
            "comment": ("Package list read from the project's manifests only: "
                        "direct dependencies, version constraints, no licences."
                        if declared else
                        "Static inventory of the scanned source; not guaranteed complete."),
        },
        "packages": spdx_pkgs,
        "relationships": relationships,
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = list(extracted.values())
    return doc


def _spdx_declared(licenses: list[str], extracted: dict[str, dict]) -> str:
    if not licenses:
        return "NOASSERTION"
    expr = _spdx_expression(licenses)
    if expr:
        return expr
    refs = []
    for name in licenses:
        known = _SPDX_UPPER.get(name.strip().upper())
        if known:
            refs.append(known)
            continue
        slug = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-") or "unknown"
        ref, n = f"LicenseRef-{slug}", 1
        while ref in extracted and extracted[ref]["name"] != name:
            n += 1
            ref = f"LicenseRef-{slug}-{n}"
        extracted.setdefault(ref, {"licenseId": ref, "name": name,
                                   "extractedText": name})
        refs.append(ref)
    return " AND ".join(refs)
