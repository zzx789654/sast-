"""Custom scanner rules: store, validate and list them.

Users write these in the browser and they are executed by a scanner, so the
module is strict about what it will store: the name must be a plain slug (no
separators, no dots), the extension is decided here rather than taken from the
request, and every resolved path is checked to still be inside the rules
directory before anything is written or read.

Built-in templates are served from code and can never be overwritten -- they
are the worked examples someone starts from.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import config

# A rule name is a slug. Rejecting everything else is what keeps "../../etc"
# and "a/b" out; the extension is added here, never supplied by the caller.
# \Z, not $: "$" also matches before a trailing newline, which let a name
# like "abc\n" through and produced a file called "abc\n.yaml".
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,48}\Z")

MAX_RULE_BYTES = 256 * 1024      # a rule file is text; this is already generous
MAX_RULES_PER_ENGINE = 100       # a person writes a handful, not thousands
VALIDATE_TIMEOUT = 60

# Validating runs a scanner, so each request costs a process and a thread.
# Nothing authenticates the caller, so bound how many can run at once --
# otherwise a handful of requests starve the threadpool and stall scans.
MAX_CONCURRENT_VALIDATIONS = 2
_validation_slots = threading.Semaphore(MAX_CONCURRENT_VALIDATIONS)
_write_lock = threading.Lock()

ENGINES = {
    "semgrep": {"ext": ".yaml", "language": "yaml"},
    "trivy": {"ext": ".rego", "language": "rego"},
}


def rules_dir(engine: str) -> Path:
    return config.RULES_DIR / engine


@dataclass
class RuleFile:
    engine: str
    name: str
    builtin: bool
    content: str


# --------------------------------------------------------------- built-ins
# Worked examples rather than a blank page: each one is a complete, valid rule
# that fires on an obvious mistake, so it can be run first and edited second.
BUILTIN: dict[str, dict[str, str]] = {
    "semgrep": {
        "example-dangerous-eval": """# Flags eval() on a value that came from outside the program.
# Try it on:  def f(s): return eval(s)
rules:
  - id: dangerous-eval
    patterns:
      - pattern: eval($X)
    message: >-
      eval() runs whatever it is given. If $X can be influenced by a user,
      this is remote code execution. Parse the value instead.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
      category: security
""",
        "example-internal-url": """# Flags hard-coded internal hostnames, which leak infrastructure layout
# and break as soon as the environment changes.
rules:
  - id: hardcoded-internal-url
    pattern-regex: https?://[a-z0-9.-]*\\.(internal|corp|local)\\b
    message: >-
      Internal hostname written into the source. Move it to configuration so
      it can differ per environment and is not published with the code.
    severity: WARNING
    languages: [generic]
    paths:
      exclude:
        - "*.md"
        - "*.txt"
    metadata:
      category: security
""",
    },
    "trivy": {
        "example-dockerfile-root": """# METADATA
# title: Container runs as root
# description: A Dockerfile that ends up as root gives an attacker who escapes
#   the process full control of everything the container can reach.
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: CUSTOM-DKR-001
#   avd_id: CUSTOM-DKR-001
#   severity: HIGH
#   short_code: no-root-user
#   recommended_action: Add a non-root USER near the end of the Dockerfile.
#   input:
#     selector:
#       - type: dockerfile
package custom.dockerfile.CUSTOMDKR001

import rego.v1

deny contains res if {
	some i
	stage := input.Stages[_]
	cmd := stage.Commands[i]
	cmd.Cmd == "user"
	cmd.Value[0] == "root"
	res := result.new("Container runs as root; add a non-root USER.", cmd)
}
""",
    },
}


# Rego is a real language, and Trivy evaluates it with OPA's full built-in set.
# Confirmed on this deployment: a rule calling http.send made a live request
# out of the container and got a 200 back. Since the rule editor has no login,
# that turns "write a check" into "make the server fetch a URL of my choosing",
# which is a way to probe the internal network or post scanned source code
# somewhere. --check-namespaces only decides which package is evaluated; it is
# not a sandbox.
#
# Custom checks legitimately need to inspect `input` and compare values. None
# of them need the network, the clock, the environment or the filesystem, so
# those built-ins are refused before a rule is ever stored or run.
FORBIDDEN_REGO = (
    ("http.send", "makes network requests"),
    ("net.lookup_ip_addr", "resolves hostnames"),
    ("opa.runtime", "reads the process environment"),
    ("rego.parse_module", "compiles further Rego at run time"),
    ("trace", "writes to the evaluation trace"),
)

# Match the call, not the word: "http.send(" and "http.send (", but not a
# mention inside a comment or a string such as "do not use http.send".
_REGO_CALL = "{}\\s*\\("


def check_rego_builtins(content: str) -> Optional[str]:
    """Return why this Rego is refused, or None when it is acceptable."""
    # Strip comments first: a rule may legitimately explain why it avoids
    # these, and refusing that would be confusing.
    body = "\n".join(line.split("#", 1)[0] for line in content.splitlines())
    for name, why in FORBIDDEN_REGO:
        if re.search(_REGO_CALL.format(re.escape(name)), body):
            return (f"{name}() is not allowed in a custom check because it "
                    f"{why}. A check should only inspect the scanned project.")
    return None


def _safe_path(engine: str, name: str) -> Path:
    """Resolve a rule path, refusing anything that escapes the rules dir."""
    if engine not in ENGINES:
        raise ValueError(f"unknown engine '{engine}'")
    if not NAME_RE.match(name or ""):
        raise ValueError(
            "name must be lower-case letters, digits, dash or underscore "
            "(no dots, no slashes), 1-49 characters")
    base = rules_dir(engine).resolve()
    path = (base / (name + ENGINES[engine]["ext"])).resolve()
    # Belt and braces: the slug already cannot traverse, but a symlinked rules
    # directory could still land the resolved path somewhere else.
    if path.parent != base:
        raise ValueError("invalid rule name")
    return path


def list_rules(engine: Optional[str] = None) -> list[dict]:
    """Every rule the UI can offer, built-ins first."""
    engines = [engine] if engine else list(ENGINES)
    out: list[dict] = []
    for eng in engines:
        if eng not in ENGINES:
            continue
        for name in sorted(BUILTIN.get(eng, {})):
            out.append({"engine": eng, "name": name, "builtin": True,
                        "language": ENGINES[eng]["language"]})
        d = rules_dir(eng)
        if d.is_dir():
            for f in sorted(d.glob("*" + ENGINES[eng]["ext"])):
                if f.stem in BUILTIN.get(eng, {}):
                    continue          # a saved copy never shadows a built-in
                out.append({"engine": eng, "name": f.stem, "builtin": False,
                            "language": ENGINES[eng]["language"]})
    return out


def read_rule(engine: str, name: str) -> RuleFile:
    if name in BUILTIN.get(engine, {}):
        return RuleFile(engine, name, True, BUILTIN[engine][name])
    path = _safe_path(engine, name)
    if not path.is_file():
        raise FileNotFoundError(name)
    return RuleFile(engine, name, False, path.read_text("utf-8"))


def save_rule(engine: str, name: str, content: str) -> dict:
    """Validate, then write. A rule that does not compile is never stored."""
    if name in BUILTIN.get(engine, {}):
        raise ValueError("built-in templates cannot be overwritten; "
                         "save it under a different name")
    path = _safe_path(engine, name)
    data = (content or "").encode("utf-8")
    if not data.strip():
        raise ValueError("rule is empty")
    if len(data) > MAX_RULE_BYTES:
        raise ValueError(f"rule is larger than {MAX_RULE_BYTES // 1024} KB")

    result = validate_rule(engine, content)
    if not result["ok"]:
        # Storing a rule that cannot run would fail later, during a scan,
        # where it is far harder to connect to what was typed.
        raise ValueError(result["message"] or "rule failed validation")

    path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        # Cap the number of rules, not just each rule's size: the name space is
        # large enough to keep writing new ones until the volume is full.
        existing = {f.stem for f in path.parent.glob("*" + ENGINES[engine]["ext"])}
        if name not in existing and len(existing) >= MAX_RULES_PER_ENGINE:
            raise ValueError(
                f"at most {MAX_RULES_PER_ENGINE} {engine} rules; delete one first")
        # Write to a temp file and rename: a crash or a concurrent save must
        # never leave half a rule on disk, because a scan would then run it.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
    return {"engine": engine, "name": name, "builtin": False,
            "validation": result}


def delete_rule(engine: str, name: str) -> None:
    if name in BUILTIN.get(engine, {}):
        raise ValueError("built-in templates cannot be deleted")
    path = _safe_path(engine, name)
    if not path.is_file():
        raise FileNotFoundError(name)
    path.unlink()


# -------------------------------------------------------------- validation

def validate_rule(engine: str, content: str) -> dict:
    """Ask the scanner itself whether the rule compiles.

    Anything less -- a YAML parse, a regex over the text -- would accept rules
    that the scanner then rejects at scan time. The tool is the only authority
    on its own rule format.
    """
    if engine not in ENGINES:
        return {"ok": False, "message": f"unknown engine '{engine}'"}

    # Check this before running anything: validation executes the rule, so a
    # rule that reaches the network would already have done so by the time the
    # scanner reported back.
    if engine == "trivy":
        refused = check_rego_builtins(content)
        if refused:
            return {"ok": False, "checked": True, "message": refused}

    binary = "semgrep" if engine == "semgrep" else "trivy"
    if not shutil.which(binary):
        return {"ok": False, "checked": False,
                "message": f"{binary} is not installed, so the rule cannot be checked"}

    if not _validation_slots.acquire(timeout=30):
        return {"ok": False, "checked": False,
                "message": "too many rule checks running; try again in a moment"}
    try:
        return _run_validation(engine, content, binary)
    finally:
        _validation_slots.release()


def _run_validation(engine: str, content: str, binary: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="rule-check-") as tmp:
        tmpdir = Path(tmp)
        if engine == "semgrep":
            rule = tmpdir / ("rule" + ENGINES[engine]["ext"])
            rule.write_text(content, encoding="utf-8")
            cmd = ["semgrep", "validate", str(rule)]
        else:
            # Trivy has no "validate"; the closest honest check is to run it
            # over an empty directory and see whether the policy compiles.
            rdir = tmpdir / "rego"
            rdir.mkdir()
            (rdir / "check.rego").write_text(content, encoding="utf-8")
            target = tmpdir / "empty"
            target.mkdir()
            cmd = ["trivy", "fs", "--scanners", "misconfig",
                   "--config-check", str(rdir),
                   "--check-namespaces", "custom",
                   "--format", "json", "--quiet", str(target)]

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                cmd, capture_output=True, text=True,
                timeout=VALIDATE_TIMEOUT, shell=False,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "checked": True,
                    "message": f"validation timed out after {VALIDATE_TIMEOUT}s"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "checked": True, "message": str(exc)[:500]}

    # Trivy prints its whole scan report on success, which is noise next to
    # an editor; only its errors are worth showing there.
    err = (proc.stderr or "").strip()
    out = (proc.stdout or "").strip()
    combined = "\n".join(x for x in (err, out) if x)

    if proc.returncode == 0 and not _has_rego_error(combined, engine):
        message = _first_useful(combined) if engine == "semgrep" else ""
        return {"ok": True, "checked": True, "message": message}
    return {"ok": False, "checked": True,
            "message": _first_useful(err or combined)
            or f"exited with {proc.returncode}"}


def _has_rego_error(output: str, engine: str) -> bool:
    """Trivy exits 0 even when a policy fails to compile, so read the output."""
    if engine != "trivy":
        return False
    lowered = output.lower()
    return any(s in lowered for s in
               ("rego_parse_error", "rego_type_error", "rego_compile_error",
                "failed to load", "compile error"))


# The rule is checked in a temp directory, so the tool's messages point at a
# path the user has never seen. Referring to "your rule" is what they expect.
_TMP_PATH_RE = re.compile(r"\S*rule-check-\w+[\\/][\w.-]+")


def _first_useful(output: str) -> str:
    """The part of the tool's output worth showing next to the editor."""
    output = _TMP_PATH_RE.sub("your rule", output)
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    keep = [l for l in lines
            if "error" in l.lower() or "invalid" in l.lower()
            or "valid" in l.lower()]
    return "\n".join((keep or lines)[:12])[:2000]


# ------------------------------------------------- feeding rules to a scan

def materialize(engine: str, names: list[str], dest: Path) -> list[Path]:
    """Write the chosen rules into a scan's workspace.

    Rules are copied per scan rather than pointed at in place, so that editing
    a rule midway through a scan cannot change what that scan is running.
    """
    out: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    for name in names:
        try:
            rule = read_rule(engine, name)
        except (FileNotFoundError, ValueError):
            continue          # a deleted rule is skipped, not fatal
        path = dest / (rule.name + ENGINES[engine]["ext"])
        path.write_text(rule.content, encoding="utf-8")
        out.append(path)
    return out
