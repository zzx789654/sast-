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
from .models import (
    Job, JobStatus, ScanTarget, ToolPhase, ToolResult, ToolStatus,
)
from .source import clone_git, extract_zip, resolve_local_path


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=config.MAX_WORKERS, thread_name_prefix="job"
        )
        config.WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    # ---- lifecycle ----------------------------------------------------
    def new_job(self, target: ScanTarget, tools: list[str]) -> Job:
        job_id = uuid.uuid4().hex[:12]
        job = Job(id=job_id, target=target, requested_tools=tools)
        with self._lock:
            self._jobs[job_id] = job
            self._prune_locked()
        (config.WORKSPACE_DIR / job_id).mkdir(parents=True, exist_ok=True)
        return job

    def job_dir(self, job_id: str) -> Path:
        return config.WORKSPACE_DIR / job_id

    def start(self, job_id: str, source_spec: dict) -> None:
        self._pool.submit(self._run_job, job_id, source_spec)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return sorted(
                self._jobs.values(), key=lambda j: j.created_at, reverse=True
            )

    # ---- worker -------------------------------------------------------
    def _run_job(self, job_id: str, source_spec: dict) -> None:
        job = self.get(job_id)
        if job is None:
            return
        job.status = JobStatus.RUNNING
        job.started_at = _now()
        job.stage = "preparing source"
        src_dir = self.job_dir(job_id) / "source"
        external = False  # true for local-path mode (do not delete user's dir)
        try:
            scan_root = self._prepare_source(source_spec, src_dir, job)
            external = source_spec.get("kind") == "path"
            job.stage = "inventorying files"
            try:
                job.inventory = inventory(scan_root)
            except Exception:  # noqa: BLE001 - inventory is best-effort
                job.inventory = {}
            job.stage = "scanning"
            self._run_adapters(job, scan_root)
            job.compute_summary().compute_progress()
            job.stage = "done"
            job.status = JobStatus.DONE
        except Exception as exc:  # noqa: BLE001 - report any prep/scan failure
            job.status = JobStatus.ERROR
            job.stage = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.logs.append(job.error)
        finally:
            job.finished_at = _now()
            if not config.KEEP_WORKSPACES:
                self._cleanup(job_id, external)

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

        def run_one(adapter) -> None:
            placeholder = job.results[adapter.name]
            placeholder.phase = ToolPhase.RUNNING
            placeholder.started_at = _now()
            job.compute_progress()
            try:
                result = adapter.scan(scan_root)
            except Exception as exc:  # noqa: BLE001
                result = ToolResult(
                    tool=adapter.name, kind=adapter.kind,
                    status=ToolStatus.ERROR,
                    error=f"{type(exc).__name__}: {exc}",
                ).compute_summary()
            result.phase = ToolPhase.FINISHED
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
             if j.status in (JobStatus.DONE, JobStatus.ERROR)),
            key=lambda j: j.created_at,
        )
        while len(self._jobs) > config.MAX_JOBS_RETAINED and finished:
            victim = finished.pop(0)
            self._jobs.pop(victim.id, None)


def _now() -> str:
    from .models import _now as now
    return now()


manager = JobManager()
