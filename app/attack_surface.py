"""Attack surface map: which doors a project opens and where it connects to.

The scanners answer "what is wrong in this code". This answers a different
question -- what does the code expose (HTTP routes), what does its front end
call, and which outside hosts does it talk to -- so a reviewer can see the
shape of the thing before reading the findings.

Static only, and that is a real limit, not a footnote: nothing here runs the
project or sends a request. A URL assembled at run time, a route registered
by reflection, or a path a reverse proxy adds is invisible to it. The UI
says so next to every result. Every flag ("no auth detected", "nobody calls
this") is an inference from source and is labelled as one.

The scanned tree is untrusted input. Files are read, never executed; symlinks
are not followed; every file, the file count and the total time are capped,
and anything left unread makes the result "incomplete" with the reason --
the same rule the scanners follow (round 41): not having looked is not the
same as having found nothing.
"""
from __future__ import annotations

import ast
import bisect
import ipaddress
import json
import os
import posixpath
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

from .inventory import SKIP_DIRS

#: Said wherever the map is handed out (download, MCP), so a reader of the
#: file alone still learns what it cannot contain.
NOTE = ("Static analysis: the code was read, not run. Not detectable: URLs "
        "built at run time (string concatenation, config files, environment "
        "variables), connections made inside third-party packages, routes "
        "registered dynamically or by reflection, paths added by a reverse "
        "proxy or API gateway, and real traffic (which endpoints are called, "
        "how often, with what). 'no auth detected' and 'unreferenced' are "
        "inferences from source; confirm them by hand. Does not affect the "
        "verdict.")

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20_000
TIME_BUDGET_S = 60.0
MAX_ENDPOINTS = 2000
MAX_HOSTS = 500
MAX_LOCATIONS = 20
MAX_SKIPPED = 50
MAX_RISKS = 500

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
          ".html", ".htm"}
JAVA_EXT = {".java"}
PHP_EXT = {".php"}
CONFIG_EXT = {".json", ".yml", ".yaml", ".properties", ".toml", ".ini",
              ".xml", ".conf", ".cfg"}
# Always front end: markup and component files run in the browser.
FRONTEND_EXT = {".html", ".htm", ".vue", ".svelte", ".jsx", ".tsx"}
# Lockfiles are full of registry URLs; listing them as "outside hosts" would
# bury the hosts the code actually talks to.
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "npm-shrinkwrap.json", "composer.lock", "poetry.lock",
             "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock"}
FRONTEND_DIRS = {"static", "public", "assets", "frontend", "client", "web",
                 "www", "renderer", "components", "pages", "views", "ui"}

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

# Names that mark an authentication check. Matched against decorator,
# dependency and middleware names only, never against route paths.
AUTH_RE = re.compile(
    r"auth|login|jwt|token|current_user|permission|role|guard|protect|"
    r"verify|session|security|isauthenticated|ensureloggedin|passport|admin",
    re.IGNORECASE)

# Hosts that appear in nearly every project and are not connections:
# XML namespaces, schema ids, licence headers, documentation examples.
NOISE_HOSTS = {"www.w3.org", "w3.org", "json-schema.org", "schemas.xmlsoap.org",
               "schemas.microsoft.com", "xmlns.com", "purl.org",
               "www.apache.org", "opensource.org", "example.com",
               "www.example.com", "example.org", "example.net"}


# ------------------------------------------------------------------ helpers
class _Text:
    """A file's text with line lookup by offset."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._nl = [i for i, ch in enumerate(text) if ch == "\n"]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._nl, offset - 1) + 1


_PARAM_RE = re.compile(
    r"\$\{[^}]{0,200}\}|\{[^}/]{0,100}\}|<[^>/]{0,100}>|:[A-Za-z_]\w{0,60}|"
    r"\(\?P<[^>]{1,60}>[^)]{0,100}\)")


def normalize_path(path: str) -> str:
    """One spelling per route: parameters become {}, no query, no trailing /."""
    # Parameters first: a Django regex group "(?P<pk>...)" contains a "?"
    # that is not a query string.
    p = _PARAM_RE.sub("{}", path.strip())
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = p.lstrip("^").rstrip("$")
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path if path.startswith("/") else "/" + path
    return "/" + (prefix.strip("/") + "/" + path.lstrip("/")).strip("/")


def _template(raw: str) -> str:
    """A JS template literal's ${expr} parts become {param}."""
    return re.sub(r"\$\{[^}]{0,200}\}", "{param}", raw)


# Query parameters whose value is a credential: ?password=..., &api_key=...
_SECRET_PARAM_RE = re.compile(
    r"([?&;][\w.-]{0,40}(?:pass|pwd|secret|token|key|auth|sig|credential)[\w.-]{0,40}=)[^&#;\s]*",
    re.IGNORECASE)


def mask_credentials(url: str) -> str:
    """Hide every credential a URL can carry: user:secret@, token@, ?password=.

    A password may contain "@", "/", "?" or "#", so with a ":" in front of an
    "@" everything up to the *last* "@" is treated as userinfo. That can mask
    a little too much (an "@" later in a path or query), which only costs
    accuracy of the host shown -- the safe way to be wrong. Without a ":", a
    bare token ends at the first "/", "?" or "#" (so registry/@scope/pkg is
    a path, not a token).
    """
    url = _SECRET_PARAM_RE.sub(r"\1***", url)
    i = url.find("//")
    if i == -1:
        return url
    head = url[i + 2:]
    colon = head.find(":")
    if colon != -1 and head.find("@", colon) != -1:
        at = head.rfind("@")
        return url[:i + 2] + head[:colon] + ":***" + head[at:]
    stop = min((j for j in (head.find("/"), head.find("?"), head.find("#")) if j != -1),
               default=len(head))
    at = head.rfind("@", 0, stop)
    if at == -1:
        return url
    return url[:i + 2] + "***" + head[at:]


def is_frontend(rel: str, text: str) -> bool:
    """Heuristic: does this file run in a browser? Labelled as heuristic in the UI."""
    ext = posixpath.splitext(rel)[1].lower()
    if ext in FRONTEND_EXT:
        return True
    if ext not in JS_EXT:
        return False
    if _BACKEND_JS_RE.search(text):
        return False
    parts = {p.lower() for p in rel.split("/")[:-1]}
    if parts & FRONTEND_DIRS:
        return True
    return bool(re.search(r"\b(document|window)\.", text))


_BACKEND_JS_RE = re.compile(
    r"""(?:require\(\s*|from\s+)['"](?:express|koa|fastify|http|https|fs|"""
    r"""child_process|net|node:[a-z_]+)['"]""")


# ------------------------------------------------------------ Python (ast)
def _const_str(node) -> "str | None":
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _name_of(node) -> str:
    """The trailing name of a Name/Attribute/Call, for auth matching."""
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _has_auth_dep(node) -> bool:
    """dependencies=[Depends(get_current_user)] or a list of such."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_has_auth_dep(e) for e in node.elts)
    if isinstance(node, ast.Call) and _name_of(node.func) in ("Depends", "Security"):
        return any(AUTH_RE.search(_name_of(a)) for a in node.args) or \
            _name_of(node.func) == "Security"
    return False


def _py_framework(tree: ast.Module) -> str:
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for m in mods:
            root = m.split(".")[0]
            if root in ("fastapi", "starlette"):
                return "fastapi"
            if root in ("flask", "quart"):
                return "flask"
            if root == "django":
                return "django"
    return ""


def extract_python(rel: str, text: str, ctx: "_Context") -> None:
    ctx.check()          # parsing cannot be interrupted, so do not start late
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        ctx.skip(rel, f"Python syntax error: {type(exc).__name__}")
        return

    # Auth-decorated names, for Django views wired up in another file.
    for node in ast.walk(tree):
        ctx.tick()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(AUTH_RE.search(_name_of(d)) for d in node.decorator_list):
                ctx.auth_views.add(node.name)
        elif isinstance(node, ast.ClassDef):
            if any(AUTH_RE.search(_name_of(b)) for b in node.bases) or any(
                    AUTH_RE.search(_name_of(d)) for d in node.decorator_list):
                ctx.auth_views.add(node.name)

    framework = _py_framework(tree)
    if not framework:
        return
    ctx.frameworks.add(framework)
    stem = posixpath.splitext(posixpath.basename(rel))[0]

    # name -> (prefix, router-level auth); "from .users import router as r"
    routers: dict[str, tuple[str, bool]] = {}
    imports: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        ctx.tick()
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            mod = node.module.split(".")[-1]
            for a in node.names:
                imports[a.asname or a.name] = (mod, a.name)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            ctor = _name_of(call.func)
            if ctor in ("APIRouter", "Blueprint"):
                prefix = _const_str(_kw(call, "prefix") or _kw(call, "url_prefix")) or ""
                auth = _has_auth_dep(_kw(call, "dependencies"))
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        routers[tgt.id] = (prefix, auth)
        # app.include_router(users.router, prefix="/u") / register_blueprint
        if isinstance(node, ast.Call) and _name_of(node.func) in (
                "include_router", "register_blueprint") and node.args:
            prefix = _const_str(_kw(node, "prefix") or _kw(node, "url_prefix")) or ""
            auth = _has_auth_dep(_kw(node, "dependencies"))
            arg = node.args[0]
            key = None
            if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                key = (arg.value.id, arg.attr)
            elif isinstance(arg, ast.Name):
                key = imports.get(arg.id, (stem, arg.id))
            if key and (prefix or auth):
                ctx.py_mounts[key] = (prefix, auth)

    if framework == "django":
        _django_urls(rel, tree, ctx)
        return

    for node in ast.walk(tree):
        ctx.tick()
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        other_auth = any(
            AUTH_RE.search(_name_of(d)) for d in node.decorator_list
            if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr in HTTP_METHODS | {"route", "api_route", "websocket"}))
        args = node.args.args + node.args.kwonlyargs
        defaults = node.args.defaults + [d for d in node.args.kw_defaults if d]
        dep_auth = any(_has_auth_dep(d) for d in defaults) or any(
            a.annotation is not None and "Depends" in ast.dump(a.annotation)
            and AUTH_RE.search(ast.dump(a.annotation)) for a in args)
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name)):
                continue
            verb = dec.func.attr
            if verb not in HTTP_METHODS | {"route", "api_route", "websocket"}:
                continue
            path = _const_str(dec.args[0]) if dec.args else _const_str(_kw(dec, "path"))
            if path is None:
                continue
            obj = dec.func.value.id
            if verb in ("route", "api_route"):
                methods_node = _kw(dec, "methods")
                methods = [m.upper() for m in (
                    [_const_str(e) for e in methods_node.elts]
                    if isinstance(methods_node, (ast.List, ast.Tuple)) else ["GET"]) if m]
            elif verb == "websocket":
                methods = ["WS"]
            else:
                methods = [verb.upper()]
            prefix, r_auth = routers.get(obj, ("", False))
            auth = other_auth or dep_auth or r_auth or _has_auth_dep(_kw(dec, "dependencies"))
            for m in methods:
                ctx.add_route(m, _join(prefix, path), framework, rel, dec.lineno,
                              auth, mount_key=(stem, obj))


def _django_urls(rel: str, tree: ast.Module, ctx: "_Context") -> None:
    module = posixpath.splitext(rel)[0].replace("/", ".")
    for node in ast.walk(tree):
        ctx.tick()
        if not (isinstance(node, ast.Call) and _name_of(node.func) in (
                "path", "re_path", "url") and len(node.args) >= 2):
            continue
        route = _const_str(node.args[0])
        if route is None:
            continue
        view = node.args[1]
        if isinstance(view, ast.Call) and _name_of(view.func) == "include":
            target = _const_str(view.args[0]) if view.args else None
            if target:
                ctx.django_includes.append((module, route, target))
            continue
        if isinstance(view, ast.Call) and _name_of(view.func) == "as_view":
            view_name = _name_of(view.func.value) if isinstance(view.func, ast.Attribute) else ""
            wrapped_auth = False
        else:
            view_name = _name_of(view)
            wrapped_auth = isinstance(view, ast.Call) and bool(AUTH_RE.search(_name_of(view.func)))
        ctx.django_routes.append({
            "module": module, "route": route, "view": view_name,
            "wrapped_auth": wrapped_auth, "file": rel, "line": node.lineno})


# ------------------------------------------------------------------ JS / TS
def _str(n: int) -> str:
    """A quoted string literal whose quote is capture group n (content is n+1)."""
    return r"""(['"`])((?:(?!\%d)[^\\\n]){0,500})\%d""" % (n, n)


_EXPRESS_ROUTE_RE = re.compile(
    r"\b([A-Za-z_$][\w$]{0,40})\.(get|post|put|delete|patch|options|head|all)"
    r"\(\s*(['\"`])(/[^'\"`\s]{0,300})\3([^\n]{0,300})")
_EXPRESS_USE_RE = re.compile(
    r"\b[A-Za-z_$][\w$]{0,40}\.use\(\s*(['\"`])(/[^'\"`\s]{0,300})\1\s*,\s*"
    r"(?:require\(\s*['\"]([^'\"]{1,200})['\"]\s*\)|([A-Za-z_$][\w$]{0,60}))")
_REQUIRE_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*require\(\s*['\"]([^'\"]{1,200})['\"]\s*\)"
    r"|import\s+([A-Za-z_$][\w$]{0,60})\s+from\s+['\"]([^'\"]{1,200})['\"]")
_ROUTER_DEF_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*(?:express\.)?Router\(")
_NOT_ROUTERS = {"axios", "$", "jQuery", "http", "https", "request", "superagent",
                "got", "ky", "fetch", "client", "api", "map", "cache", "params",
                "headers", "res", "req", "searchParams", "localStorage"}

_FETCH_RE = re.compile(r"\bfetch\(\s*" + _str(1) + r"([^;\n]{0,200})")
_AXIOS_RE = re.compile(
    r"\baxios\.(get|post|put|delete|patch|head|options|request)\(\s*" + _str(2))
_AXIOS_CFG_RE = re.compile(r"\baxios\(\s*\{([^}]{0,400})\}")
_JQ_RE = re.compile(r"(?:\$|jQuery)\.(get|post|getJSON)\(\s*" + _str(2))
_JQ_AJAX_RE = re.compile(r"(?:\$|jQuery)\.ajax\(\s*\{([^}]{0,400})\}")
_XHR_RE = re.compile(
    r"\.open\(\s*['\"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*,\s*" + _str(2),
    re.IGNORECASE)
_SOCKET_RE = re.compile(r"\bnew\s+(WebSocket|EventSource)\(\s*" + _str(2))
_CLIENT_RE = re.compile(
    r"\b[A-Za-z_$][\w$]{0,40}\.(get|post|put|delete|patch)\(\s*(['\"`])(/[^'\"`\s]{1,300})\2")
_LITERAL_RE = re.compile(r"(['\"`])(/api/[^'\"`\s]{0,300})\1")
_CFG_URL_RE = re.compile(r"\burl\s*:\s*" + _str(1))
_CFG_METHOD_RE = re.compile(r"\b(?:method|type)\s*:\s*['\"](\w{3,7})['\"]", re.IGNORECASE)


def _resolve_js(rel: str, spec: str, files: "set[str]") -> "str | None":
    """'./routes/users' imported from rel -> the scanned file it names."""
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
    for cand in (base, *(base + e for e in (".js", ".ts", ".mjs", ".cjs")),
                 *(base + "/index" + e for e in (".js", ".ts"))):
        if cand in files:
            return cand
    return None


def extract_js(rel: str, src: _Text, ctx: "_Context", frontend: bool) -> None:
    text = src.text
    backend = bool(re.search(
        r"""(?:require\(\s*|from\s+)['"]express['"]|\bexpress\(\)|\bexpress\.Router\(""",
        text))
    if backend:
        ctx.frameworks.add("express")
        local_prefix: dict[str, str] = {}
        imported: dict[str, str] = {}
        for m in _REQUIRE_RE.finditer(text):
            ctx.tick()
            name, spec = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            target = _resolve_js(rel, spec, ctx.files)
            if target:
                imported[name] = target
        routers = {m.group(1) for m in _ROUTER_DEF_RE.finditer(text)}
        for m in _EXPRESS_USE_RE.finditer(text):
            ctx.tick()
            prefix, spec, var = m.group(2), m.group(3), m.group(4)
            if spec:
                target = _resolve_js(rel, spec, ctx.files)
                if target:
                    ctx.js_mounts[target] = prefix
            elif var in imported:
                ctx.js_mounts[imported[var]] = prefix
            elif var in routers:
                local_prefix[var] = prefix
        for m in _EXPRESS_ROUTE_RE.finditer(text):
            ctx.tick()
            obj, verb, path, rest = m.group(1), m.group(2), m.group(4), m.group(5)
            if obj in _NOT_ROUTERS:
                continue
            method = "ANY" if verb == "all" else verb.upper()
            # Middleware sits between the path and the handler on the same call.
            auth = bool(AUTH_RE.search(rest.split("=>")[0].split("function")[0]))
            ctx.add_route(method, _join(local_prefix.get(obj, ""), path), "express",
                          rel, src.line(m.start()), auth, js_file=rel)
        return

    seen: set[tuple[int, str]] = set()

    def call(method: str, raw: str, offset: int, kind: str) -> None:
        ctx.tick()
        # A URL in source can carry credentials (https://user:pass@host);
        # mask before it is stored anywhere.
        url = mask_credentials(_template(raw.strip()))
        if not url or not (url.startswith("/") or "://" in url):
            return
        seen.add((offset, url))
        ctx.add_call(method.upper(), url, rel, src.line(offset), kind, frontend)

    for m in _FETCH_RE.finditer(text):
        mm = _CFG_METHOD_RE.search(m.group(3))
        call(mm.group(1) if mm else "GET", m.group(2), m.start(), "fetch")
    for m in _AXIOS_RE.finditer(text):
        call("?" if m.group(1) == "request" else m.group(1), m.group(3), m.start(), "axios")
    for m in _AXIOS_CFG_RE.finditer(text):
        ctx.tick()
        u = _CFG_URL_RE.search(m.group(1))
        if u:
            mm = _CFG_METHOD_RE.search(m.group(1))
            call(mm.group(1) if mm else "GET", u.group(2), m.start(), "axios")
    for m in _JQ_RE.finditer(text):
        call("POST" if m.group(1) == "post" else "GET", m.group(3), m.start(), "jquery")
    for m in _JQ_AJAX_RE.finditer(text):
        ctx.tick()
        u = _CFG_URL_RE.search(m.group(1))
        if u:
            mm = _CFG_METHOD_RE.search(m.group(1))
            call(mm.group(1) if mm else "GET", u.group(2), m.start(), "jquery")
    for m in _XHR_RE.finditer(text):
        call(m.group(1), m.group(3), m.start(), "xhr")
    for m in _SOCKET_RE.finditer(text):
        call("WS" if m.group(1) == "WebSocket" else "SSE", m.group(3), m.start(),
             m.group(1).lower())
    covered = {off for off, _ in seen}
    for m in _CLIENT_RE.finditer(text):
        ctx.tick()
        if m.start() not in covered and not text[max(0, m.start() - 6):m.start()].endswith("axios."):
            call(m.group(1), m.group(3), m.start(), "client")
    known = {u for _, u in seen}
    for m in _LITERAL_RE.finditer(text):
        ctx.tick()
        url = _template(m.group(2))
        if url not in known:
            call("?", m.group(2), m.start(), "literal")
            known.add(url)


# --------------------------------------------------------------- Java Spring
# How far around an annotation to look for its class keyword or its method's
# annotation block. Bounded so a file of nothing but annotations stays linear.
_WINDOW = 1000
_SPRING_RE = re.compile(r"@(Request|Get|Post|Put|Delete|Patch)Mapping\b(?:\s*\(([^)]{0,500})\))?")
# What may sit between a class-level annotation and "class": whitespace, more
# annotations, modifiers. Each alternative starts differently, and the
# argument list allows at most one space before "(", so a failed match cannot
# backtrack through many ways of splitting the same text.
_SPRING_PRELUDE_RE = re.compile(
    r"(?:\s|@\w+(?:[ \t]?\([^)]{0,500}\))?|"
    r"\b(?:public|protected|private|abstract|final|static)\b)*")
_CLASS_RE = re.compile(r"\bclass\b")
_SPRING_AUTH_RE = re.compile(r"@(PreAuthorize|Secured|RolesAllowed|PostAuthorize)\b")
_STR_LIT_RE = re.compile(r'"([^"\n]{0,300})"')


def _spring_paths(args: "str | None") -> list[str]:
    if not args:
        return [""]
    m = re.search(r"\b(?:value|path)\s*=\s*(\{[^}]{0,400}\}|\"[^\"\n]{0,300}\")", args)
    chunk = m.group(1) if m else args.split("method")[0]
    paths = _STR_LIT_RE.findall(chunk)
    return paths or [""]


def extract_java(rel: str, src: _Text, ctx: "_Context") -> None:
    text = src.text
    if "Mapping" not in text:
        return
    classes = [m.start() for m in _CLASS_RE.finditer(text)]
    class_auth = bool(classes) and bool(_SPRING_AUTH_RE.search(text, 0, classes[0]))
    class_prefix = [""]
    for m in _SPRING_RE.finditer(text):
        ctx.tick()
        i = bisect.bisect_left(classes, m.end())
        nxt = classes[i] if i < len(classes) else -1
        if nxt != -1 and nxt - m.end() <= _WINDOW and \
                _SPRING_PRELUDE_RE.fullmatch(text, m.end(), nxt):
            class_prefix = _spring_paths(m.group(2))
            continue
        kind, args = m.group(1), m.group(2)
        if kind == "Request":
            methods = re.findall(r"RequestMethod\.(\w+)", args or "") or ["ANY"]
        else:
            methods = [kind.upper()]
        # The annotation block this mapping belongs to: back to the previous
        # statement or block end, forward to the method's opening brace.
        lo = max(0, m.start() - _WINDOW)
        start = max(text.rfind(";", lo, m.start()), text.rfind("}", lo, m.start()),
                    text.rfind("{", lo, m.start()), lo - 1)
        end = text.find("{", m.end(), m.end() + _WINDOW)
        auth = class_auth or bool(_SPRING_AUTH_RE.search(
            text, start + 1, end if end != -1 else m.end()))
        ctx.frameworks.add("spring")
        for cp in class_prefix:
            for p in _spring_paths(args):
                for meth in methods:
                    ctx.add_route(meth.upper(), _join(cp, p), "spring", rel,
                                  src.line(m.start()), auth)


# --------------------------------------------------------------- PHP Laravel
_LARAVEL_ROUTE_RE = re.compile(
    r"Route::(get|post|put|patch|delete|options|any|match)\(\s*"
    r"(?:\[[^\]]{0,200}\]\s*,\s*)?['\"]([^'\"]{0,300})['\"]")
_LARAVEL_GROUP_RE = re.compile(
    r"Route::((?:(?:middleware|prefix|name|controller|namespace)\([^)]{0,300}\)\s*->\s*){0,6}"
    r"(?:middleware|prefix|name|controller|namespace)\([^)]{0,300}\))\s*->\s*group\(")
_BRACE_RE = re.compile(r"[{}]")
_PHP_CLOSURE_RE = re.compile(
    r"\s*(?:static\s+)?function\s*\([^)]{0,300}\)\s*"
    r"(?:use\s*\([^)]{0,300}\)\s*)?(?::\s*\??[\w\\]{1,100}\s*)?\{")


def brace_pairs(text: str, ctx: "_Context") -> dict[int, int]:
    """'{' offset -> offset just past its '}', in one pass over the braces."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for m in _BRACE_RE.finditer(text):
        ctx.tick()
        if m.group() == "{":
            stack.append(m.start())
        elif stack:
            pairs[stack.pop()] = m.end()
    return pairs


def extract_php(rel: str, src: _Text, ctx: "_Context") -> None:
    text = src.text
    if "Route::" not in text:
        return
    ctx.frameworks.add("laravel")
    # routes/api.php is mounted under /api by Laravel itself.
    base = "/api" if rel.endswith("routes/api.php") else ""
    groups = []
    pairs = None
    for g in _LARAVEL_GROUP_RE.finditer(text):
        ctx.tick()
        if pairs is None:
            pairs = brace_pairs(text, ctx)
        chain = g.group(1)
        pm = re.search(r"prefix\(\s*['\"]([^'\"]{0,200})['\"]", chain)
        mw = re.search(r"middleware\(([^)]{0,300})\)", chain)
        # Only a closure passed straight to group() is its body. A group that
        # loads a file (->group(base_path(...))) has none, and taking the next
        # "{" would hand its prefix and auth to unrelated routes.
        closure = _PHP_CLOSURE_RE.match(text, g.end())
        # An unclosed closure runs to the end of the file, as PHP would read it.
        end = pairs.get(closure.end() - 1, len(text)) if closure else g.end()
        groups.append((g.end(), end, pm.group(1) if pm else "",
                       bool(mw and "auth" in mw.group(1))))

    # Groups nest (their braces do), so one sweep with a stack finds every
    # route's enclosing groups without comparing each route to each group.
    active: list[tuple[int, str, bool]] = []      # (end, prefix, auth)
    gi = 0
    for m in _LARAVEL_ROUTE_RE.finditer(text):
        ctx.tick()
        pos = m.start()
        while gi < len(groups) and groups[gi][0] <= pos:
            gs, ge, gp, ga = groups[gi]
            gi += 1
            while active and active[-1][0] <= gs:
                active.pop()
            if ge > pos:
                pprefix, pauth = (active[-1][1], active[-1][2]) if active else (base, False)
                active.append((ge, _join(pprefix, gp) if gp else pprefix, pauth or ga))
        while active and active[-1][0] <= pos:
            active.pop()
        prefix, auth = (active[-1][1], active[-1][2]) if active else (base, False)
        verb, path = m.group(1), m.group(2)
        stmt_end = text.find(";", m.end(), m.end() + _WINDOW)
        stmt = text[m.end():stmt_end if stmt_end != -1 else m.end() + _WINDOW]
        mw = re.search(r"->\s*middleware\(([^)]{0,300})\)", stmt)
        auth = auth or bool(mw and "auth" in mw.group(1))
        if verb == "match":
            methods = [x.upper() for x in re.findall(r"['\"](\w+)['\"]",
                                                     text[m.start():m.start() + 200].split("]")[0])]
        else:
            methods = ["ANY" if verb == "any" else verb.upper()]
        for meth in methods or ["ANY"]:
            ctx.add_route(meth, _join(prefix, path), "laravel", rel,
                          src.line(m.start()), auth)


# ------------------------------------------------------------------- hosts
_URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"`<>()\\,;]{1,300}")
_CONN_RE = re.compile(
    r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|"
    r"mssql|sqlserver|jdbc:[a-z]{2,20})://[^\s'\"`<>\\,;]{1,300}")
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CLOUD_STORAGE = ("s3.amazonaws.com", ".s3.", "storage.googleapis.com",
                  "blob.core.windows.net", "firebaseio.com",
                  "firebasestorage.googleapis.com", "digitaloceanspaces.com")
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}


def classify_host(host: str) -> "str | None":
    """private | loopback | metadata | cloud_storage | third_party, or None for noise."""
    h = host.lower().strip("[]")
    if not h or h in NOISE_HOSTS or h.endswith(".example.com"):
        return None
    if h in _METADATA_HOSTS:
        return "metadata"
    if h == "localhost" or h.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if "." not in h:
            return None          # a bare word, not a host
        if any(s in h for s in _CLOUD_STORAGE):
            return "cloud_storage"
        return "third_party"
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "third_party"


class _Spans:
    """Non-overlapping spans in increasing order, as finditer yields them.

    A linear scan per lookup made a minified bundle quadratic: 1 MB on one
    line took minutes. bisect keeps each lookup logarithmic.
    """

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def add(self, start: int, end: int) -> None:
        self.starts.append(start)
        self.ends.append(end)

    def covers(self, pos: int) -> bool:
        i = bisect.bisect_right(self.starts, pos) - 1
        return i >= 0 and pos < self.ends[i]


def extract_hosts(rel: str, src: _Text, ctx: "_Context", frontend: bool) -> None:
    text = src.text
    conn_spans = _Spans()
    for m in _CONN_RE.finditer(text):
        ctx.tick()
        conn_spans.add(m.start(), m.end())
        raw = m.group(0)
        masked = mask_credentials(raw)
        parts = urlsplit(masked.replace("jdbc:", "", 1))
        # Never the whole string: what follows the authority (a query with
        # options, sometimes a password) is not part of where it connects.
        key = f"{parts.scheme}://{parts.netloc}" if parts.netloc else \
            f"{parts.scheme}://{parts.path}"
        ctx.add_host(key, "database", rel, src.line(m.start()), frontend)
    url_spans = _Spans()
    for m in _URL_RE.finditer(text):
        ctx.tick()
        if conn_spans.covers(m.start()):
            continue
        url_spans.add(m.start(), m.end())
        try:
            host = urlsplit(m.group(0)).hostname or ""
        except ValueError:
            continue
        cat = classify_host(host)
        if cat:
            ctx.add_host(host, cat, rel, src.line(m.start()), frontend)
    for m in _IP_RE.finditer(text):
        ctx.tick()
        if url_spans.covers(m.start()) or conn_spans.covers(m.start()):
            continue
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        cat = classify_host(str(ip))
        # A bare public dotted quad is usually a version number; keep only the
        # addresses that matter on their own.
        if cat in ("private", "metadata"):
            ctx.add_host(str(ip), cat, rel, src.line(m.start()), frontend)


# ------------------------------------------------------------- OpenAPI docs
_OPENAPI_NAME_RE = re.compile(r"(openapi|swagger)[^/]*\.(json|ya?ml)$", re.IGNORECASE)
# [ \t] rather than \s: \s also matches newlines, and "^\s+" over a file of
# blank lines backtracked quadratically (200 KB took minutes).
_YAML_PATH_RE = re.compile(r"^[ \t]+['\"]?(/[^'\":\s]*)['\"]?[ \t]*:[ \t]*$", re.MULTILINE)


def extract_openapi(text: str, rel: str) -> set[str]:
    if rel.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return set()
        paths = data.get("paths") if isinstance(data, dict) else None
        return {normalize_path(p) for p in paths} if isinstance(paths, dict) else set()
    return {normalize_path(p) for p in _YAML_PATH_RE.findall(text)}


# ----------------------------------------------------------------- context
class _OutOfTime(Exception):
    """The time budget ran out inside an extractor or the correlation."""


class _TooLarge(Exception):
    pass


class _Context:
    def __init__(self, files: set[str], clock=time.monotonic,
                 deadline: float = float("inf")) -> None:
        self.files = files
        self.clock = clock
        self.deadline = deadline
        self._ticks = 0
        self.reasons: list[str] = []
        self.routes: dict[tuple, dict] = {}
        self.calls: list[dict] = []
        self._call_keys: set[tuple] = set()
        self.hosts: dict[str, dict] = {}
        self.frameworks: set[str] = set()
        self.skipped: list[str] = []
        self.skipped_count = 0
        self.auth_views: set[str] = set()
        self.py_mounts: dict[tuple[str, str], tuple[str, bool]] = {}
        self.js_mounts: dict[str, str] = {}
        self.django_routes: list[dict] = []
        self.django_includes: list[tuple[str, str, str]] = []
        self.documented: set[str] = set()
        self.has_openapi = False
        self.frontend_files: set[str] = set()

    def check(self) -> None:
        if self.clock() > self.deadline:
            raise _OutOfTime

    def tick(self) -> None:
        """Called inside every per-match loop: the budget holds within a file,
        not only between files. The clock is read every 256 ticks."""
        self._ticks += 1
        if not self._ticks & 255 and self.clock() > self.deadline:
            raise _OutOfTime

    def skip(self, rel: str, why: str) -> None:
        self.skipped_count += 1
        if len(self.skipped) < MAX_SKIPPED:
            self.skipped.append(f"{rel}: {why}")

    def add_route(self, method, path, framework, rel, line, auth,
                  mount_key=None, js_file=None) -> None:
        key = (method, path, rel, line)
        if key not in self.routes:
            self.routes[key] = {
                "method": method, "path": path, "side": "backend",
                "framework": framework, "file": rel, "line": line,
                "auth": "detected" if auth else "not_detected",
                "_mount": mount_key, "_js": js_file,
            }

    def add_call(self, method, url, rel, line, kind, frontend) -> None:
        # The same call repeated in one file (a bundle) is one call; matching
        # each copy against every route would only cost time.
        key = (method, url, rel)
        if key in self._call_keys:
            return
        self._call_keys.add(key)
        self.calls.append({"method": method, "url": url, "file": rel,
                           "line": line, "kind": kind, "frontend": frontend})

    def add_host(self, host, category, rel, line, frontend) -> None:
        entry = self.hosts.get(host)
        if entry is None:
            entry = {"host": host, "category": category, "frontend": False,
                     "locations": [], "count": 0}
            self.hosts[host] = entry
        entry["count"] += 1
        entry["frontend"] = entry["frontend"] or frontend
        if len(entry["locations"]) < MAX_LOCATIONS:
            entry["locations"].append({"file": rel, "line": line, "frontend": frontend})


# --------------------------------------------------------------- correlate
def _apply_mounts(ctx: _Context) -> list[dict]:
    routes = []
    for r in ctx.routes.values():
        mk, jf = r.pop("_mount"), r.pop("_js")
        if mk and mk in ctx.py_mounts:
            prefix, auth = ctx.py_mounts[mk]
            r["path"] = _join(prefix, r["path"])
            if auth:
                r["auth"] = "detected"
        if jf and jf in ctx.js_mounts:
            r["path"] = _join(ctx.js_mounts[jf], r["path"])
        routes.append(r)

    # Django: urls.py modules chained through include().
    prefixes: dict[str, str] = {}
    for _ in range(5):          # include chains are shallow; bounded anyway
        for parent, route, target in ctx.django_includes:
            prefixes[target] = _join(prefixes.get(parent, ""), route)
    for d in ctx.django_routes:
        ctx.frameworks.add("django")
        auth = d["wrapped_auth"] or d["view"] in ctx.auth_views
        routes.append({
            "method": "ANY", "path": _join(prefixes.get(d["module"], ""), d["route"]),
            "side": "backend", "framework": "django", "file": d["file"],
            "line": d["line"], "auth": "detected" if auth else "not_detected"})
    return routes


def _match(call_path: str, route_path: str) -> bool:
    if call_path == route_path:
        return True
    short, long_ = sorted((call_path, route_path), key=len)
    if not short.strip("/{}"):
        return False
    # A front end often prepends a base URL ('/api') the route does not
    # spell out, or the other way round. Both start with "/", so a suffix
    # match always lands on a segment boundary.
    return long_.endswith(short)


def _segments(path: str) -> tuple:
    return tuple(p for p in path.split("/") if p)


def _methods_match(a: str, b: str) -> bool:
    return a == b or "?" in (a, b) or "ANY" in (a, b)


def correlate(ctx: _Context, findings: "list | None") -> dict:
    routes = _apply_mounts(ctx)
    for r in routes:
        r["norm"] = normalize_path(r["path"])
        r["called_from"] = []
        r["flags"] = []

    # A call can only match a route that ends in the same segments (see
    # _match), so index routes by their last one or two segments instead of
    # comparing every call with every route.
    by_two: dict[tuple, list] = {}
    by_one: dict[tuple, list] = {}
    single: dict[tuple, list] = {}
    for r in routes:
        segs = _segments(r["norm"])
        if len(segs) >= 2:
            by_two.setdefault(segs[-2:], []).append(r)
        else:
            single.setdefault(segs, []).append(r)
        by_one.setdefault(segs[-1:], []).append(r)

    def candidates(norm: str) -> list:
        segs = _segments(norm)
        if len(segs) >= 2:
            return by_two.get(segs[-2:], []) + single.get(segs[-1:], [])
        return by_one.get(segs, [])

    has_frontend_calls = False
    matched_all = True
    unmatched = []
    try:
        for c in ctx.calls:
            ctx.tick()
            external = "://" in c["url"]
            if external:
                try:
                    parts = urlsplit(c["url"])
                    host, path = parts.hostname or "", parts.path or "/"
                except ValueError:
                    continue
                if classify_host(host) not in ("loopback",):
                    unmatched.append({**c, "path": c["url"], "external": True})
                    continue
            else:
                path = c["url"]
            if c["frontend"]:
                has_frontend_calls = True
            norm = normalize_path(path)
            hit = False
            for r in candidates(norm):
                ctx.tick()
                if _methods_match(c["method"], r["method"]) and _match(norm, r["norm"]):
                    hit = True
                    if len(r["called_from"]) < MAX_LOCATIONS:
                        r["called_from"].append({"file": c["file"], "line": c["line"]})
            if not hit:
                unmatched.append({**c, "path": path, "external": False})
    except _OutOfTime:
        # Without every call matched, "nobody calls this" and "no route for
        # this" would be guesses; leave both out rather than mislabel.
        matched_all = False
        ctx.reasons.append("time limit reached while matching front-end calls to "
                           "routes; 'unreferenced' and 'no matching route' were not judged")

    for r in routes:
        if r["auth"] == "not_detected":
            r["flags"].append("no_auth_detected")
        if matched_all and has_frontend_calls and not r["called_from"]:
            r["flags"].append("unreferenced")
        if ctx.has_openapi and r["norm"] not in ctx.documented:
            r["flags"].append("undocumented")

    endpoints = [{k: v for k, v in r.items() if k != "norm"} for r in routes]
    for c in unmatched:          # already one per (method, url, file)
        flags = ["external"] if c["external"] else (
            ["unknown_backend"] if routes and matched_all else [])
        endpoints.append({
            "method": c["method"], "path": c["path"], "side": "frontend",
            "framework": c["kind"], "file": c["file"], "line": c["line"],
            "auth": "n/a", "flags": flags, "called_from": []})

    endpoints.sort(key=lambda e: (e["side"] != "backend", e["path"], e["method"]))
    hosts = sorted(ctx.hosts.values(), key=lambda h: (
        ["metadata", "private", "database", "cloud_storage", "loopback",
         "third_party"].index(h["category"]), h["host"]))

    secrets = []
    for f in findings or []:
        rel = f.file or ""
        frontend = rel in ctx.frontend_files or is_frontend(rel, "")
        secrets.append({"rule": f.rule_id, "file": rel, "line": f.start_line,
                        "frontend": frontend})

    risks = []
    risk_kind = {"private": "frontend_private_host", "metadata": "frontend_metadata",
                 "database": "frontend_db_connection"}
    for h in hosts:
        if h["category"] in risk_kind:
            for loc in h["locations"]:
                if loc["frontend"]:
                    risks.append({"kind": risk_kind[h["category"]], "file": loc["file"],
                                  "line": loc["line"], "detail": h["host"]})
    for s in secrets:
        if s["frontend"]:
            risks.append({"kind": "frontend_leak", "file": s["file"],
                          "line": s["line"], "detail": s["rule"]})

    backend = [e for e in endpoints if e["side"] == "backend"]
    summary = {
        "endpoints": len(endpoints),
        "backend_routes": len(backend),
        "frontend_calls": len(ctx.calls),
        "no_auth": sum("no_auth_detected" in e["flags"] for e in backend),
        "unreferenced": sum("unreferenced" in e["flags"] for e in backend),
        "undocumented": sum("undocumented" in e["flags"] for e in backend),
        "unknown_backend": sum("unknown_backend" in e["flags"] for e in endpoints),
        "hosts": len(hosts),
        "risks": len(risks),
        "secrets": len(secrets),
    }
    truncated = {"endpoints": max(0, len(endpoints) - MAX_ENDPOINTS),
                 "hosts": max(0, len(hosts) - MAX_HOSTS),
                 "risks": max(0, len(risks) - MAX_RISKS)}
    return {
        "summary": summary,
        "endpoints": endpoints[:MAX_ENDPOINTS],
        "hosts": hosts[:MAX_HOSTS],
        "secrets": secrets[:MAX_RISKS],
        "risks": risks[:MAX_RISKS],
        "truncated": truncated,
        "has_frontend_calls": has_frontend_calls,
        "has_openapi": ctx.has_openapi,
    }


# --------------------------------------------------------------------- walk
def _walk(root: Path, limit: int) -> "tuple[list[str], int]":
    """Files under root, relative and '/'-separated. Symlinks skipped.

    Stops one past limit, so a tree of millions of files is not listed in
    full just to report that it was too big.
    """
    out, links = [], 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                links += 1
                continue
            out.append(Path(full).relative_to(root).as_posix())
            if len(out) > limit:
                return out, links
    return out, links


def read_regular(path: Path, limit: int) -> "bytes | None":
    """A regular file's bytes, or None for anything else (FIFO, device, socket).

    Opened with O_NOFOLLOW, so a file swapped for a symlink after the walk
    fails instead of being followed; O_NONBLOCK, so opening a FIFO does not
    wait for a writer. The type is checked on the open descriptor, and the
    size is enforced while reading, so a file that grows is still capped.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > limit:
                raise _TooLarge
            chunks.append(chunk)
    finally:
        os.close(fd)


def collect(root: Path, findings: "list | None" = None,
            clock=time.monotonic) -> dict:
    """Map the attack surface of the tree at root. Never runs anything."""
    root = Path(root)
    started = clock()
    all_files, symlinks = _walk(root, MAX_FILES)
    ctx = _Context(set(all_files), clock=clock, deadline=started + TIME_BUDGET_S)
    if len(all_files) > MAX_FILES:
        ctx.reasons.append(f"only the first {MAX_FILES} files were read; the project has more")
        all_files = all_files[:MAX_FILES]
        ctx.files = set(all_files)

    scanned = 0
    for i, rel in enumerate(all_files):
        if clock() > ctx.deadline:
            ctx.reasons.append(f"time limit of {int(TIME_BUDGET_S)}s reached; "
                               f"{len(all_files) - i} files not read")
            break
        name = posixpath.basename(rel)
        ext = posixpath.splitext(name)[1].lower()
        is_env = name.startswith(".env")
        if not (ext in PY_EXT | JS_EXT | JAVA_EXT | PHP_EXT | CONFIG_EXT or is_env):
            continue
        if name in LOCKFILES:
            continue
        try:
            data = read_regular(root / rel, MAX_FILE_BYTES)
        except _TooLarge:
            ctx.skip(rel, f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
            continue
        except OSError as exc:
            ctx.skip(rel, f"unreadable ({type(exc).__name__})")
            continue
        if data is None or b"\x00" in data[:1024]:
            continue        # not a regular file, or binary
        src = _Text(data.decode("utf-8", errors="replace"))
        scanned += 1
        frontend = is_frontend(rel, src.text)
        if frontend:
            ctx.frontend_files.add(rel)
        try:
            if ext in PY_EXT:
                extract_python(rel, src.text, ctx)
            elif ext in JS_EXT:
                extract_js(rel, src, ctx, frontend)
            elif ext in JAVA_EXT:
                extract_java(rel, src, ctx)
            elif ext in PHP_EXT:
                extract_php(rel, src, ctx)
            if _OPENAPI_NAME_RE.search(name):
                ctx.has_openapi = True
                ctx.documented |= extract_openapi(src.text, rel)
            extract_hosts(rel, src, ctx, frontend)
        except RecursionError:
            ctx.skip(rel, "too deeply nested to parse")
        except _OutOfTime:
            ctx.reasons.append(f"time limit of {int(TIME_BUDGET_S)}s reached while "
                               f"reading {rel}; {len(all_files) - i - 1} files not read")
            break

    if ctx.skipped_count:
        ctx.reasons.append(f"{ctx.skipped_count} files could not be analysed")
    result = correlate(ctx, findings)
    result.update({
        "status": "incomplete" if ctx.reasons else "ok",
        "reason": "; ".join(ctx.reasons),
        "skipped": ctx.skipped,
        "stats": {"files_scanned": scanned, "files_skipped": ctx.skipped_count,
                  "symlinks_ignored": symlinks,
                  "frameworks": sorted(ctx.frameworks),
                  "duration_ms": int((clock() - started) * 1000)},
    })
    return result


def safe_collect(root: Path, findings: "list | None" = None) -> dict:
    """collect(), but a failure here never fails the scan it belongs to."""
    try:
        return collect(root, findings)
    except Exception as exc:  # the map is supplementary; report, don't raise
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}",
                "summary": {}, "endpoints": [], "hosts": [], "secrets": [],
                "risks": [], "skipped": [], "stats": {}, "truncated": {}}
