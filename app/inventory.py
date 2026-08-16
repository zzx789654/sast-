"""Project inventory + language detection.

Used for two things: showing the user what's actually in the project they're
about to scan (file count / size / language mix), and deciding whether a
language-specific tool has anything to work on (the "防呆" applicability check).

We deliberately do NOT try to report per-file scan progress: the integrated
tools are batch scanners that emit one report at the end and expose no reliable
machine-readable per-file progress, and the SCA tools work on lockfiles rather
than files at all. A trustworthy inventory is the honest granularity we can
offer.
"""
from __future__ import annotations

import os
from pathlib import Path

# Extension -> language key.
LANG_BY_EXT: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rb": "ruby", ".go": "go", ".java": "java", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp", ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift", ".scala": "scala", ".m": "objc", ".mm": "objc",
    ".sh": "shell", ".bash": "shell",
    ".yaml": "yaml", ".yml": "yaml", ".tf": "terraform", ".json": "json",
    ".html": "html", ".css": "css", ".scss": "css",
    ".md": "markdown", ".xml": "xml", ".sql": "sql", ".toml": "toml",
}

# Directories that are noise for a source inventory (deps, VCS, build output).
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", "out", ".gradle", ".idea", ".vscode",
    "vendor", "bin", "obj",
}


def inventory(root: Path, max_files: int = 200_000) -> dict:
    """Walk `root` and summarise it: file count, byte size, language histogram."""
    total_files = 0
    total_bytes = 0
    langs: dict[str, int] = {}
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            total_files += 1
            if total_files > max_files:
                truncated = True
                break
            lang = LANG_BY_EXT.get(os.path.splitext(fn)[1].lower(), "other")
            langs[lang] = langs.get(lang, 0) + 1
            try:
                total_bytes += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
        if truncated:
            break

    ordered = dict(sorted(langs.items(), key=lambda kv: -kv[1]))
    return {
        "total_files": total_files,
        "total_bytes": total_bytes,
        "languages": ordered,
        "truncated": truncated,
    }


def has_language(root: Path, languages: set[str]) -> bool:
    """True if `root` contains at least one file in any of `languages`.

    Early-exits on the first match, so it's cheap even on large trees.
    """
    wanted_exts = {e for e, lang in LANG_BY_EXT.items() if lang in languages}
    if not wanted_exts:
        return False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in wanted_exts:
                return True
    return False
