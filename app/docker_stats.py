"""Read per-container performance stats from the Docker Engine API.

Talks to the daemon over its unix socket using only the standard library (no
docker SDK dependency). Read-only: it lists containers and reads one-shot
stats. Guarded by config.ENABLE_DOCKER_STATS because mounting the docker socket
into a container is a privileged capability.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
from urllib.parse import quote

from .config import config


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _get(path: str, timeout: float = 5.0):
    conn = _UnixHTTPConnection(config.DOCKER_SOCKET, timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"docker API returned {resp.status}")
        return json.loads(body)
    finally:
        conn.close()


def availability() -> tuple[bool, str]:
    if not config.ENABLE_DOCKER_STATS:
        return False, ("disabled — set SAST_ENABLE_DOCKER_STATS=true and mount "
                       "the docker socket to enable")
    if not os.path.exists(config.DOCKER_SOCKET):
        return False, f"docker socket not found at {config.DOCKER_SOCKET}"
    return True, ""


def _project_filter() -> str:
    """Query string limiting the listing to our own compose project.

    Falls back to this container's own id when the compose label is missing
    (a plain "docker run"), and only as a last resort lists everything.
    """
    project = os.environ.get("COMPOSE_PROJECT_NAME", "").strip()
    if not project:
        # Compose stamps every container it creates with this label; read our
        # own to learn the project name without needing it to be configured.
        try:
            me = _get(f"/containers/{_self_id()}/json")
            project = ((me.get("Config") or {}).get("Labels") or {}).get(
                "com.docker.compose.project", "")
        except Exception:  # noqa: BLE001
            project = ""
    if project:
        flt = json.dumps({"label": [f"com.docker.compose.project={project}"]})
        return "?all=1&filters=" + quote(flt)
    return "?all=1"


def _self_id() -> str:
    """This container's id, from the cgroup or hostname."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                if "/docker/containers/" in line:
                    return line.split("/docker/containers/")[1].split("/")[0]
    except OSError:
        pass
    return os.environ.get("HOSTNAME", "")


def collect() -> dict:
    """Return {available, reason, containers:[...]} for the Monitor tab."""
    ok, reason = availability()
    if not ok:
        return {"available": False, "reason": reason, "containers": []}
    # Scope the listing to this deployment. The socket can see every container
    # on the host, and the Monitor tab is served without a login, so an
    # unfiltered list would hand out an inventory of unrelated workloads
    # (image names and tags often carry internal project or customer names).
    try:
        containers = _get("/containers/json" + _project_filter())
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot reach docker: {exc}",
                "containers": []}

    host_total = _host_memory_total()
    out = []
    for c in containers:
        names = c.get("Names") or []
        item = {
            "name": (names[0].lstrip("/") if names else c.get("Id", "")[:12]),
            "image": c.get("Image", ""),
            "state": c.get("State", ""),
            "status": c.get("Status", ""),
            "cpu_pct": None, "mem_used": None, "mem_limit": None,
            "mem_pct": None, "net_rx": None, "net_tx": None,
        }
        if c.get("State") == "running":
            try:
                item.update(_stats(c["Id"]))
            except Exception:  # noqa: BLE001 - stats are best-effort
                pass
        item["capacity"] = _capacity(item, host_total)
        out.append(item)
    _log_changes(out)
    return {"available": True, "reason": "", "containers": out}


#: Last state seen per container, so only transitions are logged. The Monitor
#: tab polls this every few seconds; writing a row each time would bury every
#: other category and grow the log by tens of thousands of rows a day for no
#: added information.
_seen: dict[str, tuple[str, str]] = {}


def _log_changes(containers: list) -> None:
    """Record starts, stops, restarts and capacity trouble. Never raises."""
    try:
        from . import events
    except Exception:  # noqa: BLE001
        return
    for c in containers:
        name = c.get("name") or ""
        if not name:
            continue
        state = c.get("state") or ""
        level_now = ((c.get("capacity") or {}).get("level")) or ""
        before = _seen.get(name)
        _seen[name] = (state, level_now)
        if before is None:
            # First sighting after a restart of this process is not an event:
            # the container was already in that state before we looked.
            continue
        was_state, was_level = before
        try:
            if state != was_state:
                events.record(
                    "docker", "state", target=name,
                    level="error" if state != "running" else "info",
                    detail=f"{was_state or 'unknown'} -> {state or 'unknown'}")
            elif level_now != was_level and level_now in ("warn", "tight"):
                # Saturation, which is the other thing worth a row: reported
                # once when it starts, not for as long as it lasts.
                reasons = ", ".join((c.get("capacity") or {}).get("reasons") or [])
                events.record(
                    "docker", "capacity", target=name,
                    level="error" if level_now == "tight" else "warn",
                    detail=f"{level_now}: {reasons}"
                           f" (cpu {c.get('cpu_pct')}%, mem {c.get('mem_pct')}%)")
        except Exception:  # noqa: BLE001 - monitoring must not break the tab
            continue


#: Headroom thresholds for the capacity verdict, in percent of the limit.
WARN_PCT = 75.0
TIGHT_PCT = 90.0


def _capacity(item: dict, host_total: int | None = None) -> dict:
    """Judge whether a container has enough headroom, not just its raw usage.

    A percentage on its own does not answer "is this enough?": 90% CPU is fine
    for a scanner that is meant to saturate its cores, while memory at 90% of a
    hard limit is how a scan gets OOM-killed. So memory is judged against its
    limit, CPU is reported for load, and an unset memory limit is called out
    because the container can then exhaust the host instead of itself.
    """
    if item.get("state") != "running":
        return {"level": "idle", "reasons": []}

    reasons: list[str] = []
    level = "ok"
    mem_pct, limit = item.get("mem_pct"), item.get("mem_limit")

    # A "limit" equal to host memory means no limit was actually set.
    unlimited = bool(limit and host_total and limit >= host_total * 0.95)
    if unlimited:
        reasons.append("mem_unlimited")
        level = "warn"
    elif mem_pct is not None:
        if mem_pct >= TIGHT_PCT:
            reasons.append("mem_tight")
            level = "tight"
        elif mem_pct >= WARN_PCT:
            reasons.append("mem_warn")
            level = "warn"

    if item.get("oom_killed"):
        reasons.append("oom_killed")
        level = "tight"
    if item.get("throttled"):
        reasons.append("cpu_throttled")
        level = "tight" if level != "tight" else level

    cpu = item.get("cpu_pct")
    if cpu is not None and cpu >= TIGHT_PCT and level == "ok":
        # Sustained high CPU is worth surfacing, but it is not a failure on its
        # own — scanners are expected to use the cores they are given.
        reasons.append("cpu_busy")
        level = "warn"

    return {"level": level, "reasons": reasons, "mem_unlimited": unlimited}


def _host_memory_total() -> int | None:
    try:
        return int(_get("/info").get("MemTotal") or 0) or None
    except Exception:  # noqa: BLE001 - informational only
        return None


def _stats(container_id: str) -> dict:
    s = _get(f"/containers/{container_id}/stats?stream=false")
    # These two are the honest "was it actually short of resources?" signals:
    # a failed memory allocation, or CPU time taken away by the quota.
    mem_failcnt = (s.get("memory_stats") or {}).get("failcnt") or 0
    throttled = ((s.get("cpu_stats") or {}).get("throttling_data") or {}
                 ).get("throttled_periods") or 0
    return {
        "cpu_pct": _cpu_percent(s),
        **_memory(s),
        **_network(s),
        "oom_killed": bool(mem_failcnt),
        "throttled": bool(throttled),
    }


def _cpu_percent(s: dict) -> float | None:
    try:
        cpu = s["cpu_stats"]
        pre = s["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        online = cpu.get("online_cpus") or len(
            cpu["cpu_usage"].get("percpu_usage") or [1])
        if sys_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / sys_delta) * online * 100.0, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return None


def _memory(s: dict) -> dict:
    try:
        mem = s["memory_stats"]
        used = mem.get("usage", 0)
        # exclude page cache when the daemon reports it
        cache = (mem.get("stats", {}) or {}).get("cache", 0)
        used = max(0, used - cache)
        limit = mem.get("limit", 0)
        pct = round(used / limit * 100.0, 1) if limit else None
        return {"mem_used": used, "mem_limit": limit, "mem_pct": pct}
    except (KeyError, TypeError):
        return {"mem_used": None, "mem_limit": None, "mem_pct": None}


def _network(s: dict) -> dict:
    rx = tx = 0
    for net in (s.get("networks") or {}).values():
        rx += net.get("rx_bytes", 0)
        tx += net.get("tx_bytes", 0)
    return {"net_rx": rx, "net_tx": tx}


# --------------------------------------------------------------- background
#: Seconds between samples. Long enough to be cheap (two API calls per
#: container), short enough that a restart is noticed while the cause is still
#: findable in the surrounding rows.
SAMPLE_SECONDS = 60

_sampler = None
_stop = None


def start_sampler() -> bool:
    """Watch container state in the background. Returns whether it started.

    Without this the state transitions are only seen when the Monitor tab is
    polled, so "the container restarted" is recorded only if somebody was
    looking. A daemon thread rather than a scheduler: it has one job, it holds
    no state worth draining, and the process exiting is a fine way to stop it.
    """
    global _sampler, _stop
    ok, _ = availability()
    if not ok or _sampler is not None:
        return False
    import threading
    _stop = threading.Event()

    def loop() -> None:
        # Sample once up front so the first real transition has something to
        # compare against, rather than being swallowed as a first sighting.
        while True:
            try:
                collect()
            except Exception:  # noqa: BLE001 - a sampler must not die of one bad read
                pass
            if _stop.wait(SAMPLE_SECONDS):
                return

    _sampler = threading.Thread(target=loop, name="docker-sampler", daemon=True)
    _sampler.start()
    return True


def stop_sampler() -> None:
    global _sampler, _stop
    if _stop is not None:
        _stop.set()
    _sampler = None
