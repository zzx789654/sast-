"""CycloneDX / SPDX export of the package inventory (round 52)."""
from __future__ import annotations

import json
from pathlib import Path

from app import sbom, sbom_export
from app.models import Job, ScanTarget
from tests.test_app import client, two_users  # noqa: F401  (pytest fixtures)

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_sbom.json"


def _job(packages, **sbom_extra) -> Job:
    job = Job(id="sbom1", target=ScanTarget(kind="path", display="demo"),
              finished_at="2026-10-10T08:00:00+08:00")
    job.sbom = {"available": True, "packages": packages, "summary": {},
                **sbom_extra}
    return job


def _trivy_job() -> Job:
    parsed = sbom._parse(json.loads(FIXTURE.read_text("utf-8")), Path("/x"))
    return _job(parsed["packages"])


# ---------------------------------------------------------------- CycloneDX
def test_cyclonedx_document_has_the_required_shape():
    doc = sbom_export.to_cyclonedx(_trivy_job())
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["timestamp"] == "2026-10-10T00:00:00Z"
    assert doc["components"], "the fixture has packages"
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs)), "bom-ref must be unique"
    express = next(c for c in doc["components"] if c["name"] == "express")
    assert express["purl"] == "pkg:npm/express@4.18.2"   # trivy's own purl
    assert express["licenses"] == [{"license": {"id": "MIT"}}]


def test_cyclonedx_carries_trivys_dependency_graph():
    doc = sbom_export.to_cyclonedx(_trivy_job())
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    known = set(deps)
    assert all(r in known for refs in deps.values() for r in refs), \
        "a dependsOn points at a component that is not in the document"
    assert deps["pkg:npm/express@4.18.2"], "express's own dependencies were lost"
    assert "pkg:npm/express@4.18.2" in deps["root-component"]  # direct dependency


def test_the_same_scan_gives_the_same_document():
    job = _trivy_job()
    assert sbom_export.to_cyclonedx(job) == sbom_export.to_cyclonedx(job)
    assert sbom_export.to_spdx(job) == sbom_export.to_spdx(job)


def test_a_declared_constraint_is_never_written_as_a_version():
    job = _job([{"name": "FastAPI", "version": ">=0.111", "ecosystem": "pip",
                 "source": "requirements.txt", "licenses": [], "category": "unknown",
                 "direct": True, "attention": False}], declared_only=True)
    comp = sbom_export.to_cyclonedx(job)["components"][0]
    assert "version" not in comp
    assert comp["purl"] == "pkg:pypi/fastapi"           # normalised, no version
    assert {"name": "sast-studio:version-constraint", "value": ">=0.111"} in comp["properties"]
    assert sbom_export.to_cyclonedx(job)["compositions"][0]["aggregate"] == "incomplete"

    pkg = sbom_export.to_spdx(job)["packages"][1]
    assert "versionInfo" not in pkg
    assert ">=0.111" in pkg["comment"]


def test_nothing_is_ever_marked_complete():
    assert sbom_export.to_cyclonedx(_trivy_job())["compositions"][0]["aggregate"] == "unknown"


def test_licences_that_are_not_spdx_ids_go_out_by_name():
    out = sbom_export._cdx_licenses(["Apache License 2.0"])
    assert out == [{"license": {"name": "Apache License 2.0"}}]
    assert sbom_export._cdx_licenses(["mit", "isc"]) == [{"expression": "MIT AND ISC"}]
    assert sbom_export._cdx_licenses(["MIT OR Apache-2.0"]) == \
        [{"expression": "MIT OR Apache-2.0"}]


def test_purls_are_built_for_each_ecosystem():
    p = sbom_export.make_purl
    assert p({"name": "@types/node", "version": "20.1.0", "ecosystem": "npm"}) \
        == "pkg:npm/%40types/node@20.1.0"
    assert p({"name": "golang.org/x/net", "version": "v0.1.0", "ecosystem": "gomod"}) \
        == "pkg:golang/golang.org/x/net@v0.1.0"
    assert p({"name": "org.slf4j:slf4j-api", "version": "2.0.9", "ecosystem": "Maven"}) \
        == "pkg:maven/org.slf4j/slf4j-api@2.0.9"
    assert p({"name": "Django_Rest", "version": "1", "ecosystem": "PyPI"}) \
        == "pkg:pypi/django-rest@1"
    assert p({"name": "x", "version": "1", "ecosystem": "something-new"}) == ""


# --------------------------------------------------------------------- SPDX
def test_spdx_document_has_the_required_shape():
    doc = sbom_export.to_spdx(_trivy_job())
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["creationInfo"]["created"] == "2026-10-10T00:00:00Z"
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids))
    for rel in doc["relationships"]:
        assert rel["spdxElementId"] in ids + ["SPDXRef-DOCUMENT"]
        assert rel["relatedSpdxElement"] in ids
    for pkg in doc["packages"]:
        for key in ("name", "downloadLocation", "filesAnalyzed",
                    "licenseConcluded", "licenseDeclared"):
            assert key in pkg
    assert any(r["relationshipType"] == "DESCRIBES" for r in doc["relationships"])


def test_spdx_unknown_licences_become_licence_refs_with_their_text():
    job = _job([{"name": "a", "version": "1", "ecosystem": "npm",
                 "licenses": ["Some Licence", "MIT"]},
                {"name": "b", "version": "1", "ecosystem": "npm",
                 "licenses": ["Some-Licence"]}])
    doc = sbom_export.to_spdx(job)
    assert doc["packages"][1]["licenseDeclared"] == "LicenseRef-Some-Licence AND MIT"
    # Two different names that slug the same way stay two refs.
    assert doc["packages"][2]["licenseDeclared"] == "LicenseRef-Some-Licence-2"
    names = {e["licenseId"]: e["name"] for e in doc["hasExtractedLicensingInfos"]}
    assert names == {"LicenseRef-Some-Licence": "Some Licence",
                     "LicenseRef-Some-Licence-2": "Some-Licence"}


# ---------------------------------------------------------------------- API
def test_both_formats_download(client):  # noqa: F811
    from app.main import manager

    job = manager.new_job(ScanTarget(kind="path", display="demo"), [])
    job.sbom = _trivy_job().sbom
    for fmt, media in (("cdx", "application/vnd.cyclonedx+json"),
                       ("spdx", "application/spdx+json")):
        res = client.get(f"/api/scans/{job.id}/sbom.{fmt}.json")
        assert res.status_code == 200, res.text
        assert res.headers["content-type"].startswith(media)
        assert f'sast-sbom-{job.id}.{fmt}.json' in res.headers["content-disposition"]
    assert client.get(f"/api/scans/{job.id}/sbom.xml.json").status_code == 404


def test_an_unreadable_inventory_is_refused_not_sent_empty(client):  # noqa: F811
    from app.main import manager

    job = manager.new_job(ScanTarget(kind="path", display="demo"), [])
    assert client.get(f"/api/scans/{job.id}/sbom.cdx.json").status_code == 409

    job.sbom = {"available": False, "reason": "trivy did not run",
                "packages": [], "summary": {}}
    assert client.get(f"/api/scans/{job.id}/sbom.cdx.json").status_code == 409

    # No manifest at all: an empty SBOM is the true answer.
    job.sbom = {"available": True, "reason": "no-manifest", "packages": [], "summary": {}}
    res = client.get(f"/api/scans/{job.id}/sbom.spdx.json")
    assert res.status_code == 200


def test_the_sbom_is_not_readable_by_another_account(two_users):  # noqa: F811
    admin, bob = two_users
    from app.main import manager

    job = manager.new_job(ScanTarget(kind="path", display="secret"), [], owner="admin")
    job.sbom = {"available": True, "packages": [], "summary": {}}
    assert bob.get(f"/api/scans/{job.id}/sbom.cdx.json").status_code == 404
    assert admin.get(f"/api/scans/{job.id}/sbom.cdx.json").status_code == 200
