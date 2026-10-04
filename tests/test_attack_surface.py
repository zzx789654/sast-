"""Attack surface map (app/attack_surface.py).

Each framework gets a small project written to tmp_path, and the tests check
what a reviewer would read off the result: method, path (with prefixes
joined), file:line, whether an auth check was seen, and the flags.
"""
from __future__ import annotations

import itertools
import json
import os
import time
from pathlib import Path

import pytest

from app import attack_surface as asf
from app.models import Finding, Severity


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def routes(result, side="backend"):
    return {(e["method"], e["path"]): e for e in result["endpoints"] if e["side"] == side}


# ------------------------------------------------------------------ helpers
@pytest.mark.parametrize("raw,norm", [
    ("/users/{id}", "/users/{}"),
    ("/users/:id/", "/users/{}"),
    ("users/<int:pk>/", "/users/{}"),
    ("^items/(?P<pk>[0-9]+)/$", "/items/{}"),
    ("/a/${x}?q=1#frag", "/a/{}"),
    ("//double//slash", "/double/slash"),
    ("/", "/"),
])
def test_normalize_path(raw, norm):
    assert asf.normalize_path(raw) == norm


def test_join_and_template():
    assert asf._join("", "x") == "/x"
    assert asf._join("", "/x") == "/x"
    assert asf._join("/api/", "/users") == "/api/users"
    assert asf._join("/api", "") == "/api"
    assert asf._template("/u/${id}/x") == "/u/{param}/x"


@pytest.mark.parametrize("raw,masked", [
    ("mongodb://app:s3cret@db:27017/x", "mongodb://app:***@db:27017/x"),
    ("redis://db:6379", "redis://db:6379"),
    ("postgres://admin:pa/ssw0rd@db/x", "postgres://admin:***@db/x"),     # "/" in password
    ("mysql://root:p@ssword@h:3306", "mysql://root:***@h:3306"),           # "@" in password
    ("https://" + "u" * 150 + ":TopSecret@h3/x", "https://" + "u" * 150 + ":***@h3/x"),
    ("https://ghp_tokenvalue@github.com/x", "https://***@github.com/x"),   # token only
    ("https://registry.npmjs.org/@babel/core", "https://registry.npmjs.org/@babel/core"),
    ("https://h/x?email=a@b.com", "https://h/x?email=a@b.com"),
    ("no scheme at all", "no scheme at all"),
    ("postgres://u:Qm?ark@h4", "postgres://u:***@h4"),                     # "?" in password
    ("https://carol:Qq#Leak@q.corp.io/z", "https://carol:***@q.corp.io/z"),  # "#" in password
    ("postgres:///db?password=EmptyNetPw", "postgres:///db?password=***"),
    ("https://h/api?api_key=abc123&x=1", "https://h/api?api_key=***&x=1"),
    ("/login?user=a&access_token=xyz", "/login?user=a&access_token=***"),
])
def test_mask_credentials(raw, masked):
    assert asf.mask_credentials(raw) == masked


def test_credentials_in_frontend_urls_never_leave_the_module(tmp_path):
    write(tmp_path, {
        "public/a.js": ("fetch('https://alice:Hunter2Secret@api.corp.io/v1/x');\n"
                        "axios.get('https://bob:S3cr3t@svc.corp.io/y');\n"),
        "srv/db.py": ("A = 'postgres://admin:pa/ssw0rd@db/x'\n"
                      "B = 'mysql://root:p@ssword@h:3306/d'\n"
                      "C = 'postgres:///db?password=EmptyNetPw'\n"),
        "public/b.js": "fetch('https://carol:Qq?Leak@q.corp.io/z');\n",
    })
    r = asf.collect(tmp_path)
    dump = json.dumps(r)
    for secret in ("Hunter2Secret", "S3cr3t", "pa/ssw0rd", "ssw0rd", "p@ssword", "ssword",
                   "Qq?Leak", "Leak", "EmptyNetPw"):
        assert secret not in dump, secret
    paths = {e["path"] for e in r["endpoints"]}
    assert "https://alice:***@api.corp.io/v1/x" in paths


@pytest.mark.parametrize("host,cat", [
    ("10.1.2.3", "private"), ("192.168.0.9", "private"), ("169.254.169.254", "metadata"),
    ("metadata.google.internal", "metadata"), ("localhost", "loopback"),
    ("api.localhost", "loopback"), ("127.0.0.1", "loopback"), ("0.0.0.0", "loopback"),
    ("169.254.1.1", "private"), ("8.8.8.8", "third_party"),
    ("bucket.s3.amazonaws.com", "cloud_storage"), ("x.firebaseio.com", "cloud_storage"),
    ("api.stripe.com", "third_party"), ("www.w3.org", None), ("a.example.com", None),
    ("", None), ("intranet", None),
])
def test_classify_host(host, cat):
    assert asf.classify_host(host) == cat


@pytest.mark.parametrize("rel,text,expected", [
    ("web/App.vue", "", True),
    ("src/page.tsx", "", True),
    ("server/app.py", "", False),
    ("server/index.js", "const express = require('express')", False),
    ("public/js/app.js", "let a = 1", True),
    ("lib/util.js", "window.foo = 1", True),
    ("lib/util.js", "module.exports = 1", False),
])
def test_is_frontend(rel, text, expected):
    assert asf.is_frontend(rel, text) is expected


def test_line_lookup():
    t = asf._Text("a\nbb\nccc")
    assert [t.line(0), t.line(2), t.line(5)] == [1, 2, 3]


# ------------------------------------------------------------------ FastAPI
def test_fastapi_prefixes_auth_and_cross_file_mounts(tmp_path):
    write(tmp_path, {
        "app/main.py": (
            "from fastapi import FastAPI, Depends\n"
            "from .routes import users\n"
            "from .routes.items import router as items_router\n"
            "from .routes import admin\n"
            "app = FastAPI()\n"
            "app.include_router(users.router, prefix='/api')\n"
            "app.include_router(items_router, prefix='/v1')\n"
            "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
            "app.include_router(other.router)\n"
            "@app.get('/health')\n"
            "def health(): ...\n"
            "@app.websocket('/ws')\n"
            "async def ws(sock): ...\n"
            "@app.api_route('/multi', methods=['GET', 'POST'])\n"
            "def multi(): ...\n"
            "@app.route('/plain')\n"
            "def plain(): ...\n"
            "@app.get(path='/kw')\n"
            "def kw(): ...\n"
            "@app.get(some_var)\n"
            "def dynamic(): ...\n"
            "@cache.cached()\n"
            "@app.get('/cached')\n"
            "def cached(): ...\n"
            "@decorator\n"
            "def notroute(): ...\n"
            "@registry['x']\n"
            "def subscripted(): ...\n"
            "@app.api_route('/dup', methods=['GET', 'GET'])\n"
            "def dup(): ...\n"
            "holder.router = APIRouter(prefix='/attr')\n"
            "app.include_router(make_router(), prefix='/made')\n"
        ),
        "app/routes/users.py": (
            "from fastapi import APIRouter, Depends, Security\n"
            "router = APIRouter(prefix='/users')\n"
            "@router.get('/{uid}')\n"
            "async def get_user(uid: int, user=Depends(get_current_user)): ...\n"
            "@router.post('/reset')\n"
            "async def reset(): ...\n"
            "@router.delete('/{uid}', dependencies=[Depends(verify_token)])\n"
            "async def delete(uid: int): ...\n"
            "@router.put('/{uid}')\n"
            "async def put(uid: int, s=Security(scheme)): ...\n"
            "@router.patch('/{uid}')\n"
            "async def patch(uid: int, u: Annotated[User, Depends(get_current_user)]): ...\n"
        ),
        "app/routes/items.py": (
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(dependencies=[Depends(auth_dep)])\n"
            "@router.get('/items')\n"
            "def items(): ...\n"
        ),
        "app/routes/admin.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.post('/admin/wipe')\n"
            "def wipe(): ...\n"
        ),
    })
    r = asf.collect(tmp_path)
    got = routes(r)
    assert got[("GET", "/api/users/{uid}")]["auth"] == "detected"
    assert got[("GET", "/api/users/{uid}")]["line"] == 3
    assert got[("GET", "/api/users/{uid}")]["file"] == "app/routes/users.py"
    assert got[("POST", "/api/users/reset")]["auth"] == "not_detected"
    assert "no_auth_detected" in got[("POST", "/api/users/reset")]["flags"]
    assert got[("DELETE", "/api/users/{uid}")]["auth"] == "detected"
    assert got[("PUT", "/api/users/{uid}")]["auth"] == "detected"
    assert got[("PATCH", "/api/users/{uid}")]["auth"] == "detected"
    assert got[("GET", "/v1/items")]["auth"] == "detected"
    assert got[("POST", "/admin/wipe")]["auth"] == "detected"   # mount-level dependency
    assert ("GET", "/health") in got and ("WS", "/ws") in got
    assert ("GET", "/multi") in got and ("POST", "/multi") in got
    assert ("GET", "/plain") in got and ("GET", "/kw") in got
    assert got[("GET", "/cached")]["auth"] == "not_detected"
    assert sum(1 for k in got if k == ("GET", "/dup")) == 1
    assert r["stats"]["frameworks"] == ["fastapi"]
    assert r["status"] == "ok"


def test_flask_blueprints_and_login_required(tmp_path):
    write(tmp_path, {
        "srv/app.py": (
            "from flask import Flask, Blueprint\n"
            "from flask_login import login_required\n"
            "app = Flask(__name__)\n"
            "bp = Blueprint('admin', __name__, url_prefix='/admin')\n"
            "@bp.route('/users', methods=['GET', 'DELETE'])\n"
            "@login_required\n"
            "def users(): ...\n"
            "@app.route('/open')\n"
            "def open_(): ...\n"
            "app.register_blueprint(bp)\n"
        ),
    })
    got = routes(asf.collect(tmp_path))
    assert got[("GET", "/admin/users")]["auth"] == "detected"
    assert got[("DELETE", "/admin/users")]["framework"] == "flask"
    assert got[("GET", "/open")]["auth"] == "not_detected"


def test_python_without_framework_is_ignored_but_syntax_errors_are_reported(tmp_path):
    write(tmp_path, {
        "plain.py": "import os\n@app.get('/x')\ndef f(): ...\n",
        "broken.py": "def (:\n",
    })
    r = asf.collect(tmp_path)
    assert r["endpoints"] == []
    assert r["status"] == "incomplete"
    assert any("broken.py" in s and "syntax" in s for s in r["skipped"])


# ------------------------------------------------------------------- Django
def test_django_includes_and_view_auth(tmp_path):
    write(tmp_path, {
        "proj/urls.py": (
            "from django.urls import path, include, re_path\n"
            "urlpatterns = [path('api/', include('proj.core.urls')),\n"
            "               path('dyn/', include(some_module)),\n"
            "               path(var_route, view)]\n"
        ),
        "proj/core/urls.py": (
            "from django.urls import path, re_path\n"
            "from django.contrib.auth.decorators import login_required\n"
            "from . import views\n"
            "urlpatterns = [\n"
            "  path('items/<int:pk>/', views.item),\n"
            "  path('open/', views.open_view),\n"
            "  re_path(r'^raw/(?P<pk>[0-9]+)/$', login_required(views.raw)),\n"
            "  path('cbv/', views.Secret.as_view()),\n"
            "  path('cbv2/', as_view()),\n"
            "]\n"
        ),
        "proj/core/views.py": (
            "from django.contrib.auth.decorators import login_required\n"
            "from django.contrib.auth.mixins import LoginRequiredMixin\n"
            "@login_required\n"
            "def item(request, pk): ...\n"
            "def open_view(request): ...\n"
            "class Secret(LoginRequiredMixin, View): ...\n"
            "@method_decorator(login_required, name='dispatch')\n"
            "class Other(View): ...\n"
        ),
    })
    r = asf.collect(tmp_path)
    got = routes(r)
    assert got[("ANY", "/api/items/<int:pk>")]["auth"] == "detected"
    assert got[("ANY", "/api/open")]["auth"] == "not_detected"
    assert got[("ANY", "/api/^raw/(?P<pk>[0-9]+)/$")]["auth"] == "detected"
    assert got[("ANY", "/api/cbv")]["auth"] == "detected"
    assert got[("ANY", "/api/cbv2")]["auth"] == "not_detected"
    assert "django" in r["stats"]["frameworks"]


# ------------------------------------------------------------------ Express
def test_express_routes_mounts_and_middleware(tmp_path):
    write(tmp_path, {
        "server/index.js": (
            "const express = require('express');\n"
            "const app = express();\n"
            "const router = express.Router();\n"
            "const users = require('./users');\n"
            "import orders from './orders';\n"
            "const ext = require('lodash');\n"
            "app.use('/admin', router);\n"
            "app.use('/v2', users);\n"
            "app.use('/o', orders);\n"
            "app.use('/inline', require('./inline'));\n"
            "app.use('/pkg', require('some-pkg'));\n"
            "app.use('/unknown', notImported);\n"
            "router.post('/reset', requireAuth, (req, res) => {});\n"
            "router.get('/debug', (req, res) => {});\n"
            "app.all('/any', function (req, res) {});\n"
            "axios.get('/not/a/route');\n"
        ),
        "server/users.js": "const express = require('express');\nconst r = express.Router();\nr.get('/list', h);\n",
        "server/orders/index.ts": "import express from 'express';\nconst r = express.Router();\nr.put('/:id', passport.authenticate('jwt'), h);\n",
        "server/inline.js": "const express = require('express');\nconst r = express.Router();\nr.delete('/x', h);\n",
    })
    r = asf.collect(tmp_path)
    got = routes(r)
    assert got[("POST", "/admin/reset")]["auth"] == "detected"
    assert got[("GET", "/admin/debug")]["auth"] == "not_detected"
    assert ("GET", "/v2/list") in got
    assert got[("PUT", "/o/:id")]["auth"] == "detected"
    assert ("DELETE", "/inline/x") in got
    assert ("ANY", "/any") in got
    assert ("GET", "/not/a/route") not in got
    assert r["stats"]["frameworks"] == ["express"]


# --------------------------------------------------------------- front end
def test_frontend_calls_match_routes_and_flag_the_rest(tmp_path):
    write(tmp_path, {
        "api/main.py": (
            "from fastapi import FastAPI\napp = FastAPI()\n"
            "@app.get('/api/users/{uid}')\ndef u(uid): ...\n"
            "@app.post('/api/login')\ndef login(): ...\n"
            "@app.get('/api/items')\ndef items(): ...\n"
            "@app.get('/internal/debug')\ndef dbg(): ...\n"
            "@app.post('/api/orders')\ndef orders(): ...\n"
        ),
        "web/src/api.js": (
            "fetch(`/api/users/${id}`);\n"
            "fetch('/api/orders', { method: 'POST', body });\n"
            "axios.post('/api/login', u);\n"
            "axios.request('/api/items');\n"
            "axios({ method: 'delete', url: '/api/export' });\n"
            "axios({ data: 1 });\n"
            "$.get('/api/items');\n"
            "$.post('/api/nope');\n"
            "jQuery.ajax({ url: '/api/ajax', type: 'PUT' });\n"
            "$.ajax({ data: 2 });\n"
            "xhr.open('GET', '/api/xhr');\n"
            "new WebSocket('wss://push.example.org/feed');\n"
            "new EventSource('/api/stream');\n"
            "client.get('/users/{uid}');\n"
            "const p = '/api/literal/thing';\n"
            "fetch('relative/no/slash');\n"
            "fetch('http://localhost:3000/api/items');\n"
            "fetch('https://api.github.com/repos');\n"
            "document.title = 'x';\n"
        ),
        "web/src/dup.js": "window.x = 1;\nconst a = '/api/items';\nconst b = '/api/items';\n",
    })
    r = asf.collect(tmp_path)
    back = routes(r)
    assert back[("GET", "/api/users/{uid}")]["called_from"][0] == {"file": "web/src/api.js", "line": 1}
    assert back[("GET", "/api/items")]["called_from"]
    assert back[("POST", "/api/orders")]["called_from"]
    assert back[("POST", "/api/login")]["called_from"]
    assert "unreferenced" in back[("GET", "/internal/debug")]["flags"]
    front = routes(r, "frontend")
    assert "unknown_backend" in front[("DELETE", "/api/export")]["flags"]
    assert "unknown_backend" in front[("POST", "/api/nope")]["flags"]
    assert ("PUT", "/api/ajax") in front
    assert ("GET", "/api/xhr") in front
    assert ("SSE", "/api/stream") in front
    assert ("?", "/api/literal/thing") in front
    assert front[("WS", "wss://push.example.org/feed")]["flags"] == ["external"]
    assert ("GET", "https://api.github.com/repos") in front
    assert not any("relative" in p for _, p in front)
    assert r["has_frontend_calls"] is True
    assert r["summary"]["unknown_backend"] >= 2


def test_unreferenced_needs_some_frontend_and_unknown_needs_some_backend(tmp_path):
    write(tmp_path, {"api.py": "from flask import Flask\napp=Flask(1)\n@app.route('/x')\ndef x(): ...\n"})
    r = asf.collect(tmp_path)
    assert routes(r)[("GET", "/x")]["flags"] == ["no_auth_detected"]
    assert r["has_frontend_calls"] is False

    other = tmp_path / "fe"
    write(other, {"public/a.js": "fetch('/api/whatever');\n"})
    r2 = asf.collect(other)
    assert routes(r2, "frontend")[("GET", "/api/whatever")]["flags"] == []


def test_match_rules():
    assert asf._match("/api/users/{}", "/api/users/{}")
    assert asf._match("/users/{}", "/api/users/{}")          # base URL left off
    assert not asf._match("/sers/{}", "/api/users/{}")       # not on a segment boundary
    assert not asf._match("/{}", "/api/users/{}")            # only a parameter
    assert asf._methods_match("?", "POST") and asf._methods_match("GET", "ANY")
    assert not asf._methods_match("GET", "POST")


def test_resolve_js():
    files = {"a/b.js", "a/c/index.ts"}
    assert asf._resolve_js("a/x.js", "./b", files) == "a/b.js"
    assert asf._resolve_js("a/x.js", "./c", files) == "a/c/index.ts"
    assert asf._resolve_js("a/x.js", "./missing", files) is None
    assert asf._resolve_js("a/x.js", "express", files) is None


# ------------------------------------------------------------------- Spring
def test_spring_class_prefix_methods_and_auth(tmp_path):
    write(tmp_path, {
        "src/ReportController.java": (
            "@RestController\n"
            "@RequestMapping(\"/api/reports\")\n"
            "public class ReportController {\n"
            "    @GetMapping(\"/{id}\")\n"
            "    @PreAuthorize(\"hasRole('USER')\")\n"
            "    public Report get(@PathVariable long id) { return null; }\n"
            "\n"
            "    @RequestMapping(value = {\"/a\", \"/b\"}, method = RequestMethod.POST)\n"
            "    public void post() { }\n"
            "    @RequestMapping(path = \"/c\", method = {RequestMethod.GET, RequestMethod.PUT})\n"
            "    public void c() { }\n"
            "    @DeleteMapping\n"
            "    public void del() { }\n"
            "    @RequestMapping(\"/any\")\n"
            "    public void any() { }\n"
            "}\n"
        ),
        "src/Secured.java": (
            "@Secured(\"ROLE_ADMIN\")\n"
            "@RestController\n"
            "public class Secured {\n"
            "    @PostMapping(\"/admin\")\n"
            "    public void a() { }\n"
            "}\n"
        ),
        "src/Plain.java": "public class Plain { }\n",
        "src/Weird.java": "@GetMapping(\"/eof\")",
    })
    got = routes(asf.collect(tmp_path))
    assert got[("GET", "/api/reports/{id}")]["auth"] == "detected"
    assert got[("GET", "/api/reports/{id}")]["line"] == 4
    assert got[("POST", "/api/reports/a")]["auth"] == "not_detected"
    assert ("POST", "/api/reports/b") in got
    assert ("GET", "/api/reports/c") in got and ("PUT", "/api/reports/c") in got
    assert ("DELETE", "/api/reports") in got
    assert ("ANY", "/api/reports/any") in got
    assert got[("POST", "/admin")]["auth"] == "detected"
    assert ("GET", "/eof") in got


# ------------------------------------------------------------------ Laravel
def test_laravel_groups_prefixes_and_middleware(tmp_path):
    write(tmp_path, {
        "routes/api.php": (
            "<?php\n"
            "Route::get('/status', [StatusController::class, 'show']);\n"
            "Route::middleware(['auth:sanctum'])->prefix('v1')->group(function () {\n"
            "    Route::post('/orders', [OrderController::class, 'store']);\n"
            "    if ($x) { Route::put('nested', 'X@y'); }\n"
            "});\n"
            "Route::prefix('pub')->group(function () {\n"
            "    Route::get('/page', 'P@show');\n"
            "});\n"
            "Route::delete('/items/{id}', 'ItemController@destroy')->middleware('auth');\n"
            "Route::match(['get', 'post'], '/both', 'B@x');\n"
            "Route::any('/whatever', 'W@x')"
        ),
        "routes/web.php": "<?php\nRoute::get('home', 'H@x');\nRoute::name('x')->group(function () {\n",
        "app/Plain.php": "<?php echo 1;\n",
    })
    got = routes(asf.collect(tmp_path))
    assert got[("GET", "/api/status")]["auth"] == "not_detected"
    assert got[("POST", "/api/v1/orders")]["auth"] == "detected"
    assert got[("PUT", "/api/v1/nested")]["auth"] == "detected"
    assert got[("GET", "/api/pub/page")]["auth"] == "not_detected"
    assert got[("DELETE", "/api/items/{id}")]["auth"] == "detected"
    assert ("GET", "/api/both") in got and ("POST", "/api/both") in got
    assert ("ANY", "/api/whatever") in got
    assert ("GET", "/home") in got          # web.php has no /api prefix


def test_brace_pairs():
    ctx = asf._Context(set())
    assert asf.brace_pairs("a{b{c}d}e}{", ctx) == {3: 6, 1: 8}


def test_laravel_group_nesting_sweep(tmp_path):
    """Routes after a closed group, in nested groups, and in a group with no brace."""
    write(tmp_path, {"routes/web.php": (
        "<?php\n"
        "Route::prefix('a')->group(function () {\n"
        "  Route::get('/one', 'X@y');\n"
        "  Route::prefix('b')->middleware('auth')->group(function () {\n"
        "    Route::get('/two', 'X@y');\n"
        "  });\n"
        "  Route::get('/three', 'X@y');\n"
        "});\n"
        "Route::prefix('gone')->group(function () { });\n"
        "Route::prefix('c')->group(function () { });\n"
        "Route::get('/four', 'X@y');\n"
        "Route::prefix('nobrace')->group($callable);\n"
        "Route::get('/five', 'X@y');\n")})
    got = routes(asf.collect(tmp_path))
    assert got[("GET", "/a/one")]["auth"] == "not_detected"
    assert got[("GET", "/a/b/two")]["auth"] == "detected"
    assert got[("GET", "/a/three")]["auth"] == "not_detected"
    assert ("GET", "/four") in got and ("GET", "/five") in got


# -------------------------------------------------------------------- hosts
def test_hosts_categories_masking_and_risks(tmp_path):
    write(tmp_path, {
        "web/src/config.js": (
            "const API = 'http://10.0.3.15:8080';\n"
            "const META = 'http://169.254.169.254/latest';\n"
            "const DB = 'postgres://u:pw@db.internal:5432/x';\n"
            "const S3 = 'https://shop.s3.amazonaws.com/a.png';\n"
            "const NS = 'http://www.w3.org/2000/svg';\n"
            "const BAD = 'http://[::1';\n"
            "document.body;\n"
        ),
        "server/db.py": (
            "URL = 'mongodb://app:s3cret@mongo:27017/shop'\n"
            "CB = 'mongodb://m2/db?cb=http://cb.callback.io/x'\n"
            "J = 'jdbc:mysql://root:pw@10.0.0.9:3306/db'\n"
            "HOST = '192.168.1.20'\n"
            "VER = '1.2.3.4'\n"
            "NOTIP = '999.1.1.1'\n"
        ),
        ".env.example": "REDIS_URL=redis://cache:6379\n",
        "package-lock.json": '{"resolved": "https://registry.npmjs.org/x"}',
        "README.md": "https://docs.example.org",
        "bin.json": "\x00\x01https://hidden.example.net",
    })
    r = asf.collect(tmp_path)
    hosts = {h["host"]: h for h in r["hosts"]}
    assert hosts["10.0.3.15"]["category"] == "private" and hosts["10.0.3.15"]["frontend"]
    assert hosts["169.254.169.254"]["category"] == "metadata"
    assert "postgres://u:***@db.internal:5432" in hosts
    assert "mongodb://app:***@mongo:27017" in hosts
    assert "mysql://root:***@10.0.0.9:3306" in hosts
    assert "redis://cache:6379" in hosts
    assert hosts["shop.s3.amazonaws.com"]["category"] == "cloud_storage"
    assert hosts["192.168.1.20"]["category"] == "private"
    assert "1.2.3.4" not in hosts and "www.w3.org" not in hosts
    assert "registry.npmjs.org" not in hosts and "docs.example.org" not in hosts
    assert "hidden.example.net" not in hosts
    assert "cb.callback.io" not in hosts      # part of the connection string
    assert not any("s3cret" in h or ":pw@" in h for h in hosts)
    kinds = {x["kind"] for x in r["risks"]}
    assert kinds == {"frontend_private_host", "frontend_metadata", "frontend_db_connection"}
    # sorted most worrying first
    assert r["hosts"][0]["category"] == "metadata"


def test_host_locations_are_capped(tmp_path):
    write(tmp_path, {"a.yml": "\n".join(f"u{i}: http://10.0.0.1/" for i in range(30))})
    h = asf.collect(tmp_path)["hosts"][0]
    assert h["count"] == 30 and len(h["locations"]) == asf.MAX_LOCATIONS


def test_connection_string_without_host_is_kept_whole(tmp_path):
    write(tmp_path, {"x.properties": "url=mongodb:///var/run/mongo.sock\n"})
    hosts = [h["host"] for h in asf.collect(tmp_path)["hosts"]]
    assert hosts == ["mongodb:///var/run/mongo.sock"]


# ----------------------------------------------------------------- openapi
def test_openapi_marks_undocumented_routes(tmp_path):
    write(tmp_path, {
        "app.py": ("from fastapi import FastAPI\napp=FastAPI()\n"
                   "@app.get('/documented/{id}')\ndef a(id): ...\n"
                   "@app.get('/secret')\ndef b(): ...\n"),
        "openapi.json": '{"paths": {"/documented/{id}": {}}}',
    })
    got = routes(asf.collect(tmp_path))
    assert "undocumented" not in got[("GET", "/documented/{id}")]["flags"]
    assert "undocumented" in got[("GET", "/secret")]["flags"]


def test_openapi_parsing_variants():
    assert asf.extract_openapi("not json", "openapi.json") == set()
    assert asf.extract_openapi("[1]", "openapi.json") == set()
    assert asf.extract_openapi('{"paths": []}', "swagger.json") == set()
    yaml = "openapi: 3.0.0\npaths:\n  /a/{id}:\n    get: {}\n  '/b':\n    post: {}\n"
    assert asf.extract_openapi(yaml, "openapi.yaml") == {"/a/{}", "/b"}


# ------------------------------------------------------------------ secrets
def test_gitleaks_findings_become_secrets_and_frontend_risks(tmp_path):
    write(tmp_path, {"web/app.vue": "<template/>", "server/x.py": "x=1"})
    findings = [
        Finding(tool="gitleaks", rule_id="aws-access-key", severity=Severity.HIGH,
                file="web/app.vue", start_line=3),
        Finding(tool="gitleaks", rule_id="generic", severity=Severity.HIGH,
                file="server/x.py", start_line=1),
        Finding(tool="gitleaks", rule_id="generic", severity=Severity.HIGH,
                file="", start_line=None),
    ]
    r = asf.collect(tmp_path, findings)
    assert r["summary"]["secrets"] == 3
    assert [s["frontend"] for s in r["secrets"]] == [True, False, False]
    assert r["risks"] == [{"kind": "frontend_secret", "file": "web/app.vue",
                           "line": 3, "detail": "aws-access-key"}]


# --------------------------------------------------------- limits & safety
def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    write(outside, {"secret.py": "from flask import Flask\napp=Flask(1)\n@app.route('/leak')\ndef f(): ...\n"})
    proj = tmp_path / "proj"
    write(proj, {"ok.py": "x = 1\n"})
    os.symlink(outside / "secret.py", proj / "link.py")
    os.symlink(outside, proj / "linkdir")
    r = asf.collect(proj)
    assert r["endpoints"] == []
    assert r["stats"]["symlinks_ignored"] == 1


def test_oversize_and_unreadable_files_make_it_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(asf, "MAX_FILE_BYTES", 100)
    write(tmp_path, {"big.js": "x" * 200, "small.js": "fetch('/api/x')"})
    r = asf.collect(tmp_path)
    assert r["status"] == "incomplete"
    assert any("big.js" in s for s in r["skipped"])
    assert "1 files could not be analysed" in r["reason"]

    real = asf.read_regular

    def boom(path, limit):
        if path.name == "small.js":
            raise PermissionError("no")
        return real(path, limit)
    monkeypatch.setattr(asf, "read_regular", boom)
    monkeypatch.setattr(asf, "MAX_FILE_BYTES", 1000)
    r2 = asf.collect(tmp_path)
    assert any("small.js: unreadable" in s for s in r2["skipped"])


def test_skipped_list_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(asf, "MAX_SKIPPED", 2)
    write(tmp_path, {f"b{i}.py": "def (:\n" for i in range(4)})
    r = asf.collect(tmp_path)
    assert len(r["skipped"]) == 2 and r["stats"]["files_skipped"] == 4


def test_file_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(asf, "MAX_FILES", 2)
    write(tmp_path, {f"f{i}.js": "" for i in range(4)})
    r = asf.collect(tmp_path)
    assert r["status"] == "incomplete"
    assert "only the first 2 files were read; the project has more" in r["reason"]


def test_time_budget_between_files(tmp_path):
    write(tmp_path, {"a.js": "", "b.js": ""})
    ticks = itertools.chain([0.0, 0.0], itertools.repeat(999.0))
    r = asf.collect(tmp_path, clock=lambda: next(ticks))
    assert r["status"] == "incomplete"
    assert "1 files not read" in r["reason"]


def test_time_budget_inside_a_file(tmp_path):
    """The budget is checked inside the per-match loops, not only between files."""
    # Root files are read before subdirectories: a.js first, then sub/z.js.
    write(tmp_path, {"a.js": "window.x=1;" + "".join(f"fetch('/api/{i}');" for i in range(2000)),
                     "sub/z.js": ""})
    ticks = itertools.chain([0.0, 0.0], itertools.repeat(999.0))
    r = asf.collect(tmp_path, clock=lambda: next(ticks))
    assert r["status"] == "incomplete"
    assert "while reading a.js; 1 files not read" in r["reason"]


def test_time_budget_while_matching(tmp_path):
    ctx = asf._Context(set(), clock=lambda: 999.0, deadline=0.0)
    ctx.add_route("GET", "/api/x", "flask", "a.py", 1, False)
    for i in range(600):
        ctx.add_call("GET", f"/api/{i}", "web/a.js", i, "fetch", True)
    r = asf.correlate(ctx, [])
    assert any("matching" in x for x in ctx.reasons)
    # Not judged rather than mislabelled.
    assert all("unreferenced" not in e["flags"] and "unknown_backend" not in e["flags"]
               for e in r["endpoints"])


def test_deep_nesting_is_skipped_not_fatal(tmp_path, monkeypatch):
    write(tmp_path, {"deep.py": "x = 1\n"})

    def deep(*a, **k):
        raise RecursionError
    monkeypatch.setattr(asf, "extract_python", deep)
    r = asf.collect(tmp_path)
    assert any("deeply nested" in s for s in r["skipped"])


def test_minified_bundle_on_one_line_is_fast(tmp_path):
    """1 MB on a single line, built to stress every pattern; must stay linear."""
    chunk = ("fetch('/api/a');axios.get('/api/b');x.get('/c');'''\"\"\"``"
             "http://10.0.0.1/ 10.0.0.2 mongodb://a:b@c/d $.ajax({url:'/z'}) ")
    blob = chunk * (1024 * 1024 // len(chunk))
    write(tmp_path, {"public/bundle.min.js": "window.a=1;" + blob})
    started = time.monotonic()
    r = asf.collect(tmp_path)
    assert time.monotonic() - started < 20
    assert r["status"] == "ok"
    assert r["summary"]["frontend_calls"] > 0


def test_result_lists_are_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(asf, "MAX_ENDPOINTS", 2)
    monkeypatch.setattr(asf, "MAX_HOSTS", 1)
    monkeypatch.setattr(asf, "MAX_RISKS", 1)
    write(tmp_path, {"public/a.js": "".join(f"fetch('/api/{i}');\n" for i in range(5))
                     + "u='http://10.0.0.1';v='http://10.0.0.2';"})
    r = asf.collect(tmp_path)
    assert len(r["endpoints"]) == 2 and r["truncated"]["endpoints"] == 3
    assert len(r["hosts"]) == 1 and r["truncated"]["hosts"] == 1
    assert len(r["risks"]) == 1 and r["truncated"]["risks"] == 1


def test_duplicate_frontend_calls_collapse(tmp_path):
    write(tmp_path, {"public/a.js": "fetch('/api/x');\nfetch('/api/x');\n"})
    eps = asf.collect(tmp_path)["endpoints"]
    assert len(eps) == 1


def test_safe_collect_reports_errors(tmp_path, monkeypatch):
    def fail(*a, **k):
        raise ValueError("bad")
    monkeypatch.setattr(asf, "collect", fail)
    r = asf.safe_collect(tmp_path)
    assert r["status"] == "error" and "ValueError: bad" in r["reason"]
    assert r["endpoints"] == []


def test_safe_collect_passes_through(tmp_path):
    assert asf.safe_collect(tmp_path)["status"] == "ok"


def test_invalid_urls_in_calls_and_hosts_are_skipped(tmp_path, monkeypatch):
    real = asf.urlsplit

    def picky(url, *a, **k):
        if "bad" in url:
            raise ValueError("bad url")
        return real(url, *a, **k)
    monkeypatch.setattr(asf, "urlsplit", picky)
    write(tmp_path, {"public/a.js": "fetch('https://bad.host/x');\nfetch('/api/ok');\n"})
    r = asf.collect(tmp_path)
    assert [e["path"] for e in r["endpoints"]] == ["/api/ok"]
    assert r["hosts"] == []


def test_ip_regex_rejects_invalid_octets(tmp_path):
    write(tmp_path, {"a.ini": "x=300.300.300.300\n"})
    assert asf.collect(tmp_path)["hosts"] == []


# ------------------------------------------------------------- integration
def test_orchestrator_stores_map_and_verdict_is_unchanged(tmp_path, monkeypatch):
    """The map rides along with a scan and never moves the verdict."""
    from app.orchestrator import JobManager
    from app.models import ScanTarget, JobStatus
    from app import config as cfg

    monkeypatch.setattr(cfg.config, "WORKSPACE_DIR", tmp_path / "ws")
    write(tmp_path / "src", {
        "app.py": "from flask import Flask\napp=Flask(1)\n@app.route('/open')\ndef f(): ...\n",
        "public/a.js": "fetch('http://10.0.0.5/x');\n",
    })
    jm = JobManager()
    job = jm.new_job(ScanTarget(kind="path", display="x"), tools=[])
    jm._scan(job, str(tmp_path / "src"), external=True)
    assert job.attack_surface["status"] == "ok"
    assert job.attack_surface["summary"]["risks"] == 1
    assert job.attack_surface["summary"]["no_auth"] == 1
    assert job.policy_evaluation["decision"] == "passed"
    assert job.status == JobStatus.DONE


def test_called_from_is_capped(tmp_path):
    write(tmp_path, {
        "api.py": "from flask import Flask\napp=Flask(1)\n@app.route('/api/x')\ndef x(): ...\n",
        **{f"public/p{i}.js": "fetch('/api/x');\n" for i in range(asf.MAX_LOCATIONS + 5)},
    })
    e = routes(asf.collect(tmp_path))[("GET", "/api/x")]
    assert len(e["called_from"]) == asf.MAX_LOCATIONS


def test_fifo_is_skipped_without_blocking(tmp_path):
    write(tmp_path, {"ok.js": "fetch('/api/x')"})
    os.mkfifo(tmp_path / "pipe.js")
    r = asf.collect(tmp_path)
    assert r["status"] == "ok" and r["stats"]["files_scanned"] == 1


def test_read_regular_refuses_a_symlink(tmp_path):
    (tmp_path / "real.js").write_text("x")
    os.symlink(tmp_path / "real.js", tmp_path / "link.js")
    with pytest.raises(OSError):
        asf.read_regular(tmp_path / "link.js", 100)
    assert asf.read_regular(tmp_path / "real.js", 100) == b"x"


# Each input below reproduces a case the independent review measured as
# super-linear (200 KB took 23-229 s). Now each must finish quickly.
@pytest.mark.parametrize("name,unit", [
    ("openapi.yaml", "\n "),
    ("Ctrl.java", "@GetMapping "),
    ("routes/web.php", "Route::prefix('a')->group(function(){ "),
    ("routes/api.php", "Route::get('/x', 'A@b'); "),
    ("Ctrl2.java", "@GetMapping(\"/x\")" + " " * 50 + "x class "),
])
def test_adversarial_inputs_stay_linear(tmp_path, name, unit):
    write(tmp_path, {name: unit * (400_000 // len(unit))})
    started = time.monotonic()
    r = asf.collect(tmp_path)
    assert time.monotonic() - started < 10, name
    assert r["status"] in ("ok", "incomplete")


def test_matching_many_calls_and_routes_is_fast(tmp_path):
    """5k routes x 12.5k calls took 23 s comparing every pair."""
    ctx = asf._Context(set())
    for i in range(5000):
        ctx.add_route("GET", f"/api/r{i}/{{id}}", "flask", "a.py", i, True)
    for i in range(12500):
        ctx.add_call("GET", f"/api/c{i}/1", "web/a.js", i, "fetch", True)
    started = time.monotonic()
    asf.correlate(ctx, [])
    assert time.monotonic() - started < 5


def test_same_path_other_method_is_not_a_match():
    ctx = asf._Context(set())
    ctx.add_route("POST", "/api/x", "flask", "a.py", 1, True)
    ctx.add_call("GET", "/api/x", "web/a.js", 1, "fetch", True)
    r = asf.correlate(ctx, [])
    front = [e for e in r["endpoints"] if e["side"] == "frontend"]
    assert front[0]["flags"] == ["unknown_backend"]


def test_laravel_group_without_a_closure_claims_no_routes(tmp_path):
    """->group(base_path(...)) loads a file; the next "{" is not its body."""
    write(tmp_path, {"routes/web.php": (
        "<?php\n"
        "Route::middleware('auth')->prefix('admin')->group(base_path('routes/admin.php'));\n"
        "Route::get('/public/delete-all', function () { return 1; });\n"
        "Route::prefix('x')->group(static function () use ($a): void {\n"
        "  Route::get('/in', 'A@b');\n"
        "});\n")})
    got = routes(asf.collect(tmp_path))
    assert got[("GET", "/public/delete-all")]["auth"] == "not_detected"
    assert ("GET", "/x/in") in got


def test_python_file_is_not_parsed_after_the_deadline(tmp_path):
    ctx = asf._Context(set(), clock=lambda: 999.0, deadline=0.0)
    with pytest.raises(asf._OutOfTime):
        asf.extract_python("a.py", "x = 1\n", ctx)
