"""Turn a scan request into a local directory of source code, safely.

Three input kinds are supported — uploaded zip, server-local path, git clone —
and each one is the classic place a "scan anything" tool gets attacked, so the
hardening lives here:

* zip:  Zip Slip (path escape) and Zip Bomb (size/count) protection.
* path: existence + directory checks, gated by an operator config flag.
* git:  scheme allow-list, no interactive prompts, bounded clone.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .adapters.base import run_command
from .config import config


class SourceError(Exception):
    """Raised when a scan target cannot be prepared safely."""


# ---------------------------------------------------------------- zip upload
def extract_zip(zip_path: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                count += 1
                if count > config.MAX_UNCOMPRESSED_FILES:
                    raise SourceError("archive has too many entries (possible zip bomb)")
                total += info.file_size
                if total > config.MAX_UNCOMPRESSED_BYTES:
                    raise SourceError("archive uncompressed size limit exceeded")

                target = (dest_root / info.filename).resolve()
                # Zip Slip: reject any member that escapes the destination.
                if not _within(target, dest_root):
                    raise SourceError(f"unsafe path in archive: {info.filename}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    _copy_bounded(src, out)
    except zipfile.BadZipFile as exc:
        raise SourceError(f"not a valid zip archive: {exc}") from exc
    return dest_root


def _copy_bounded(src, out, chunk=1024 * 1024) -> None:
    while True:
        data = src.read(chunk)
        if not data:
            break
        out.write(data)


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- local path
def resolve_local_path(raw_path: str) -> Path:
    if not config.ALLOW_LOCAL_PATH:
        raise SourceError("scanning server-local paths is disabled")
    if not raw_path.strip():
        raise SourceError("path is empty")
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise SourceError(f"path does not exist: {path}")
    if not path.is_dir():
        raise SourceError(f"path is not a directory: {path}")
    return path


# ---------------------------------------------------------------- git clone
def validate_git_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise SourceError("git url is empty")
    parsed = urlparse(url)
    if parsed.scheme not in config.ALLOWED_GIT_SCHEMES:
        raise SourceError(
            f"git scheme '{parsed.scheme or '(none)'}' not allowed; "
            f"permitted: {sorted(config.ALLOWED_GIT_SCHEMES)}"
        )
    if not parsed.netloc:
        raise SourceError("git url has no host")
    return url


def clone_git(url: str, dest_dir: Path) -> Path:
    url = validate_git_url(url)
    dest_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # Never block on credential/host-key prompts for an unattended clone.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_SSH_COMMAND"] = "ssh -oBatchMode=yes"
    res = run_command(
        [
            "git", "-c", "credential.helper=",
            "clone", "--depth", "1", "--no-tags",
            "--config", "core.askpass=true",
            url, str(dest_dir),
        ],
        timeout=config.GIT_CLONE_TIMEOUT,
        env=env,
    )
    if res.timed_out:
        raise SourceError("git clone timed out")
    if res.returncode != 0:
        raise SourceError("git clone failed: " + (res.stderr.strip()[:300] or "unknown"))
    return dest_dir.resolve()
