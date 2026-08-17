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


def collect() -> dict:
    """Return {available, reason, containers:[...]} for the Monitor tab."""
    ok, reason = availability()
    if not ok:
        return {"available": False, "reason": reason, "containers": []}
    try:
        containers = _get("/containers/json?all=1")
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot reach docker: {exc}",
                "containers": []}

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
        out.append(item)
    return {"available": True, "reason": "", "containers": out}


def _stats(container_id: str) -> dict:
    s = _get(f"/containers/{container_id}/stats?stream=false")
    return {
        "cpu_pct": _cpu_percent(s),
        **_memory(s),
        **_network(s),
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
