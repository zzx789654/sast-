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
    if not names:
        return list(ADAPTERS)
    return [ADAPTERS_BY_NAME[n] for n in names if n in ADAPTERS_BY_NAME]


__all__ = ["ADAPTERS", "ADAPTERS_BY_NAME", "get_adapters", "BaseAdapter"]
