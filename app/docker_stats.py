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


# ------------------------------------------------------------------- limits
#: Ceilings for a hand-typed value. Not policy -- just the point past which a
#: number is certainly a typo (someone means 2g and types 2000g).
MAX_MEMORY_BYTES = 1024 ** 4      # 1 TiB
MAX_CPUS = 512.0


def _parse_size(text: str) -> int:
    """Turn "2g", "512m", "1.5G" into bytes. Raises ValueError on nonsense."""
    raw = str(text or "").strip().lower().replace("i", "")
    if not raw:
        raise ValueError("memory limit is required")
    units = {"b": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    mult = 1
    if raw[-1] in units:
        mult = units[raw[-1]]
        raw = raw[:-1]
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"cannot read '{text}' as a size (try 2g or 512m)") from exc
    if value <= 0:
        raise ValueError("memory limit must be greater than zero")
    return int(value * mult)


def _fmt_size(n: int | None) -> str:
    """Bytes as something a person reads, which is what the UI shows."""
    if not n:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def limits() -> dict:
    """Current limits, real usage and host capacity, per container.

    All three together because a limit means nothing on its own: "2GB" is
    generous or crippling depending on what the container actually uses and
    what the host has to give.
    """
    ok, reason = availability()
    if not ok:
        return {"available": False, "reason": reason, "containers": [],
                "host_memory": None, "host_cpus": None}
    try:
        listing = _get("/containers/json" + _project_filter())
        info = _get("/info")
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot reach docker: {exc}",
                "containers": [], "host_memory": None, "host_cpus": None}

    host_memory = int(info.get("MemTotal") or 0) or None
    host_cpus = int(info.get("NCPU") or 0) or None

    out = []
    for c in listing:
        names = c.get("Names") or []
        name = names[0].lstrip("/") if names else c.get("Id", "")[:12]
        try:
            detail = _get(f"/containers/{c['Id']}/json")
        except Exception:  # noqa: BLE001
            continue
        host_cfg = detail.get("HostConfig") or {}
        mem = int(host_cfg.get("Memory") or 0)
        nano = int(host_cfg.get("NanoCpus") or 0)
        cpu_quota = int(host_cfg.get("CpuQuota") or 0)
        cpu_period = int(host_cfg.get("CpuPeriod") or 0)
        # Two ways to express a CPU limit; --cpus writes NanoCpus, older
        # setups use the quota/period pair. Report whichever is set.
        cpus = None
        if nano:
            cpus = round(nano / 1e9, 2)
        elif cpu_quota and cpu_period:
            cpus = round(cpu_quota / cpu_period, 2)

        used_mem = None
        if c.get("State") == "running":
            try:
                used_mem = _memory(_get(f"/containers/{c['Id']}/stats?stream=false")
                                   ).get("mem_used")
            except Exception:  # noqa: BLE001
                used_mem = None

        out.append({
            "name": name,
            "state": c.get("State", ""),
            "service": ((c.get("Labels") or {}).get(
                "com.docker.compose.service") or name),
            "memory": mem or None,
            "memory_text": _fmt_size(mem) if mem else "",
            "cpus": cpus,
            "memory_used": used_mem,
            "memory_used_text": _fmt_size(used_mem) if used_mem else "",
            # An unset limit is the finding, not a blank field: the container
            # can exhaust the host rather than only itself.
            "unlimited_memory": not mem,
            "unlimited_cpus": cpus is None,
        })

    return {"available": True, "reason": "", "containers": out,
            "host_memory": host_memory, "host_cpus": host_cpus,
            "host_memory_text": _fmt_size(host_memory)}


def compose_fragment(wanted: dict, host_memory: int | None = None,
                     host_cpus: int | None = None) -> str:
    """A compose snippet for the limits asked for, validated first.

    Produced rather than applied. Writing straight to the daemon would need
    write access this app deliberately does not use, and the change would be
    undone by the next deploy because compose is what defines these.
    """
    if not isinstance(wanted, dict) or not wanted:
        raise ValueError("no services given")

    lines = ["services:"]
    for service in sorted(wanted):
        spec = wanted[service] or {}
        if not str(service).replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"'{service}' is not a service name")

        mem_text = str(spec.get("memory") or "").strip()
        cpu_text = str(spec.get("cpus") or "").strip()
        if not mem_text and not cpu_text:
            continue

        body = []
        if mem_text:
            mem = _parse_size(mem_text)
            if mem > MAX_MEMORY_BYTES:
                raise ValueError(f"{mem_text} is larger than this tool accepts")
            # A limit above host memory is not a limit; it reads as one and
            # protects nothing, so it is refused rather than quietly written.
            if host_memory and mem > host_memory:
                raise ValueError(
                    f"{mem_text} is more than the host has "
                    f"({_fmt_size(host_memory)})")
            body.append(f"memory: {mem_text}")
        if cpu_text:
            try:
                cpus = float(cpu_text)
            except ValueError as exc:
                raise ValueError(f"cannot read '{cpu_text}' as a cpu count") from exc
            if cpus <= 0:
                raise ValueError("cpu limit must be greater than zero")
            if cpus > MAX_CPUS:
                raise ValueError(f"{cpu_text} is more cpus than this tool accepts")
            if host_cpus and cpus > host_cpus:
                raise ValueError(
                    f"{cpu_text} is more than the host's {host_cpus} cpus")
            body.append(f"cpus: '{cpus}'")

        lines.append(f"  {service}:")
        lines.append("    deploy:")
        lines.append("      resources:")
        lines.append("        limits:")
        for item in body:
            lines.append(f"          {item}")

    if len(lines) == 1:
        raise ValueError("no limits given")
    return "\n".join(lines)
