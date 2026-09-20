"""Job orchestration: prepare source, fan out to adapters, aggregate results.

State lives in memory (a dict of jobs) — deliberately simple, per CoreMain.
Each job runs on a background thread; within a job the selected adapters run
concurrently on a small thread pool since each one is a blocking subprocess.
"""
from __future__ import annotations

import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .adapters import get_adapters
from .config import config
from .inventory import inventory
from . import sbom
from .models import (
    Job, JobStatus, ScanTarget, ToolPhase, ToolResult, ToolStatus,
)
from .policies import evaluate_policy
from .source import clone_git, extract_zip, resolve_local_path


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        # job_id -> {"scan_root": str, "external": bool} for scans paused for
        # confirmation (source already prepared on disk, tools not yet run).
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=config.MAX_WORKERS, thread_name_prefix="job"
        )
        config.WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    # ---- lifecycle ----------------------------------------------------
    def new_job(self, target: ScanTarget, tools: list[str],
                custom_rules: "dict[str, list[str]] | None" = None,
                rulesets: "dict[str, list[str]] | None" = None,
                owner: "str | None" = None) -> Job:
        job_id = uuid.uuid4().hex[:12]
        job = Job(id=job_id, target=target, requested_tools=tools,
                  custom_rules=custom_rules or {},
                  rulesets=rulesets or {}, owner=owner)
        with self._lock:
            self._jobs[job_id] = job
            self._prune_locked()
        (config.WORKSPACE_DIR / job_id).mkdir(parents=True, exist_ok=True)
        return job

    def job_dir(self, job_id: str) -> Path:
        return config.WORKSPACE_DIR / job_id

    def start(self, job_id: str, source_spec: dict, confirm: bool = False) -> None:
        self._pool.submit(self._prepare_and_maybe_scan, job_id, source_spec, confirm)

    def confirm(self, job_id: str) -> bool:
        """Resume a scan that was paused for confirmation. Returns False if the
        job isn't in that state."""
        with self._lock:
            pending = self._pending.pop(job_id, None)
        job = self.get(job_id)
        if job is None or pending is None or job.status != JobStatus.AWAITING:
            return False
        job.status = JobStatus.RUNNING
        self._pool.submit(self._scan, job, pending["scan_root"], pending["external"])
        return True

    def cancel(self, job_id: str) -> bool:
        """Cancel a scan awaiting confirmation and clean up its workspace."""
        with self._lock:
            pending = self._pending.pop(job_id, None)
        job = self.get(job_id)
        if job is None or job.status != JobStatus.AWAITING:
            return False
        external = pending["external"] if pending else False
        job.status = JobStatus.CANCELLED
        job.stage = "cancelled"
        job.finished_at = _now()
        if not config.KEEP_WORKSPACES:
            self._cleanup(job_id, external)
        return True

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return sorted(
                self._jobs.values(), key=lambda j: j.created_at, reverse=True
            )

    # ---- worker -------------------------------------------------------
    def _prepare_and_maybe_scan(
        self, job_id: str, source_spec: dict, confirm: bool
    ) -> None:
        """Phase 1: prepare the source and inventory it. If `confirm` is set,
        pause in AWAITING for the user; otherwise go straight to scanning."""
        job = self.get(job_id)
        if job is None:
            return
        job.status = JobStatus.RUNNING
        job.started_at = _now()
        job.stage = "preparing source"
        src_dir = self.job_dir(job_id) / "source"
        external = source_spec.get("kind") == "path"
        try:
            scan_root = self._prepare_source(source_spec, src_dir, job)
            job.stage = "inventorying files"
            try:
                job.inventory = inventory(scan_root)
            except Exception:  # noqa: BLE001 - inventory is best-effort
                job.inventory = {}

            if confirm:
                job.applicability = self._applicability(job, scan_root)
                with self._lock:
                    self._pending[job_id] = {
                        "scan_root": str(scan_root), "external": external,
                    }
                job.stage = "awaiting confirmation"
                job.status = JobStatus.AWAITING
                return

            self._scan(job, str(scan_root), external)
        except Exception as exc:  # noqa: BLE001 - report any prep failure
            job.status = JobStatus.ERROR
            job.stage = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.logs.append(job.error)
            job.finished_at = _now()
            if not config.KEEP_WORKSPACES:
                self._cleanup(job_id, external)

    def _materialize_rules(self, job: Job) -> dict[str, list]:
        """Copy the job's chosen rules into its workspace.

        Copying rather than referencing means a rule edited while a scan is
        running cannot change what that scan is executing.
        """
        from . import rules as rules_mod

        out: dict[str, list] = {}
        if not job.custom_rules:
            return out
        base = config.WORKSPACE_DIR / job.id / "rules"
        for engine, names in job.custom_rules.items():
            if not names:
                continue
            try:
                paths = rules_mod.materialize(engine, names, base / engine)
            except Exception:  # noqa: BLE001 - a rule problem must not kill the scan
                continue
            if paths:
                out[engine] = paths
        return out

    def _scan(self, job: Job, scan_root: str, external: bool) -> None:
        """Phase 2: run the tools on the already-prepared source."""
        try:
            job.stage = "scanning"
            self._run_adapters(job, Path(scan_root))

            # After the tools, before cleanup removes the workspace. Its own
            # step because it answers a different question from the scanners:
            # what is in here, rather than what is wrong with it.
            job.stage = "listing packages"
            job.sbom = sbom.collect(Path(scan_root))

            job.compute_summary().compute_progress()
            job.policy_evaluation = evaluate_policy(job)
            decision = job.policy_evaluation["decision"]
            if decision == "blocked":
                job.stage = "blocked by policy"
                job.status = JobStatus.BLOCKED
            elif decision == "manual_review":
                job.stage = "awaiting policy review"
                job.status = JobStatus.POLICY_REVIEW
            else:
                job.stage = "done"
                job.status = JobStatus.DONE
        except Exception as exc:  # noqa: BLE001
            job.status = JobStatus.ERROR
            job.stage = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.logs.append(job.error)
        finally:
            job.finished_at = _now()
            if not config.KEEP_WORKSPACES:
                self._cleanup(job.id, external)

    def _applicability(self, job: Job, scan_root: Path) -> list[dict]:
        out = []
        for adapter in get_adapters(job.requested_tools):
            applicable, reason = adapter.applicability(scan_root)
            out.append({
                "name": adapter.name,
                "applicable": applicable,
                "reason": reason,
                "requirement": adapter.requirement,
            })
        return out

    def _prepare_source(self, spec: dict, src_dir: Path, job: Job) -> Path:
        kind = spec.get("kind")
        if kind == "upload":
            job.stage = "extracting uploaded archive"
            job.logs.append("extracting uploaded archive")
            return extract_zip(Path(spec["zip_path"]), src_dir)
        if kind == "git":
            job.stage = f"cloning {spec['url']}"
            job.logs.append(f"cloning {spec['url']}")
            return clone_git(spec["url"], src_dir)
        if kind == "path":
            job.stage = "reading local path"
            job.logs.append(f"scanning local path {spec['path']}")
            return resolve_local_path(spec["path"])
        raise ValueError(f"unknown source kind: {kind}")

    def _run_adapters(self, job: Job, scan_root: Path) -> None:
        adapters = get_adapters(job.requested_tools)
        # Seed every requested tool as PENDING so the UI shows the full list
        # (and an accurate 0% progress) the moment the scan starts.
        for adapter in adapters:
            job.results[adapter.name] = ToolResult(
                tool=adapter.name, kind=adapter.kind,
                status=ToolStatus.OK, phase=ToolPhase.PENDING,
            )
        job.compute_progress()
        workers = max(1, min(config.MAX_WORKERS, len(adapters)))

        # Copy the selected rules into this job's workspace before anything
        # runs, so editing a rule mid-scan cannot change what this scan uses.
        rule_files = self._materialize_rules(job)

        def run_one(adapter) -> None:
            placeholder = job.results[adapter.name]
            placeholder.phase = ToolPhase.RUNNING
            placeholder.started_at = _now()
            # Let the adapter say which part of its own work is running, so a
            # long tool shows "downloading vulnerability database" rather than
            # sitting on "running" for minutes.
            adapter._on_stage = lambda stage: setattr(placeholder, "stage", stage)
            job.compute_progress()
            try:
                result = adapter.scan(scan_root,
                                      rule_files.get(adapter.name),
                                      job.rulesets.get(adapter.name))
            except Exception as exc:  # noqa: BLE001
                result = ToolResult(
                    tool=adapter.name, kind=adapter.kind,
                    status=ToolStatus.ERROR,
                    error=f"{type(exc).__name__}: {exc}",
                ).compute_summary()
            result.phase = ToolPhase.FINISHED
            result.stage = ""
            result.started_at = placeholder.started_at
            job.results[adapter.name] = result
            job.compute_progress()
            job.logs.append(f"{adapter.name}: {result.status.value}")

        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="tool") as pool:
            futures = [pool.submit(run_one, a) for a in adapters]
            for future in as_completed(futures):
                future.result()  # re-raise nothing (run_one swallows tool errors)

    def _cleanup(self, job_id: str, external: bool) -> None:
        # Remove the job's own workspace; never touch a user-supplied path.
        shutil.rmtree(self.job_dir(job_id), ignore_errors=True)

    def _prune_locked(self) -> None:
        if len(self._jobs) <= config.MAX_JOBS_RETAINED:
            return
        finished = sorted(
            (j for j in self._jobs.values()
             if j.status in (JobStatus.DONE, JobStatus.BLOCKED,
                             JobStatus.ERROR, JobStatus.CANCELLED)),
            key=lambda j: j.created_at,
        )
        while len(self._jobs) > config.MAX_JOBS_RETAINED and finished:
            victim = finished.pop(0)
            self._jobs.pop(victim.id, None)


def _now() -> str:
    from .models import _now as now
    return now()


manager = JobManager()
