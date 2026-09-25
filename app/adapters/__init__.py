"""Adapter registry — the single list the orchestrator iterates over."""
from __future__ import annotations

from .base import BaseAdapter
from .bearer import BearerAdapter
from .gitleaks import GitleaksAdapter
from .npm_audit import NpmAuditAdapter
from .osv_scanner import OsvScannerAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

# Order is display order in the UI.
ADAPTERS: list[BaseAdapter] = [
    SemgrepAdapter(),
    BearerAdapter(),
    TrivyAdapter(),
    NpmAuditAdapter(),
    OsvScannerAdapter(),
    GitleaksAdapter(),
]

ADAPTERS_BY_NAME: dict[str, BaseAdapter] = {a.name: a for a in ADAPTERS}


def get_adapters(names: list[str] | None = None) -> list[BaseAdapter]:
    """Fresh adapters for one scan.

    `scan()` keeps that scan's rules and progress callback on the adapter, so
    sharing the instances in ADAPTERS let two scans in flight overwrite each
    other's custom rules -- one silently ran without them, the other ran with
    rule files that might already be deleted. ADAPTERS stays as the catalogue
    (names, descriptions, version probes), which only reads.
    """
    chosen = ADAPTERS if not names else \
        [ADAPTERS_BY_NAME[n] for n in names if n in ADAPTERS_BY_NAME]
    return [type(a)() for a in chosen]


__all__ = ["ADAPTERS", "ADAPTERS_BY_NAME", "get_adapters", "BaseAdapter"]
