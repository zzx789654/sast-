# SAST Studio

One web page, five security scanners. Point it at some code and it runs
**Semgrep**, **CodeQL**, **npm audit**, **OSV-Scanner** and **Gitleaks**, then
shows every finding in one severity-sorted report — no installing each tool,
memorising its flags, or reading five different output formats.

| Tool | What it does | Type |
|------|--------------|------|
| **Semgrep** | Pattern-based static analysis (Python engine) | SAST |
| **CodeQL** | Semantic analysis via a query database | SAST |
| **npm audit** | Node dependency advisories (npm registry) | SCA |
| **OSV-Scanner** | Multi-ecosystem deps vs. OSV.dev | SCA |
| **Gitleaks** | Hardcoded secret detection | Secret |

## How it's built

```
Browser (static SPA)  ──►  FastAPI  ──►  Orchestrator ──►  5 Adapters ──► tools
   index/app.js/css        REST API      (job manager)     (one per tool)
```

* **Adapter pattern.** Each tool has one adapter that does exactly three
  things: *detect availability*, *run*, *normalize output* into a shared
  `Finding` schema. The orchestrator never knows any tool's native format.
* **Graceful degradation.** A tool that isn't installed is reported as
  `unavailable` with an install hint — the scan still runs every other tool.
  So the app is useful whether you have all five tools or none.
* **Simple by design.** In-memory job store, HTTP polling for progress, a
  no-framework vanilla-JS front end. No database, no build step.

## Quick start

### Option A — Docker (recommended, free on Linux servers)

Docker Engine + Compose are free (Apache-2.0); only the Docker **Desktop** GUI
carries a fee for large orgs, and a server deployment doesn't need it.

```bash
docker compose up --build
# open http://localhost:8000
```

The image bundles Semgrep, npm audit, OSV-Scanner and Gitleaks. CodeQL is left
out on purpose (its CLI bundle is hundreds of MB and its license restricts
automated scanning of proprietary code) — mount it in to enable, see
`docker-compose.yml`.

### Option B — run locally

```bash
pip install -r requirements.txt
bash scripts/install-tools.sh        # best-effort install of the scanners
uvicorn app.main:app --reload        # http://localhost:8000
```

Any tool you don't install simply shows as unavailable.

## Using it

1. Pick a source: **upload a `.zip`**, paste a **Git URL**, or give a
   **server-local path**.
2. Tick the tools to run (unavailable ones are disabled).
3. **Start scan** — progress updates live; findings appear as each tool
   finishes.
4. Filter the combined report by severity, tool, or file.

## Security of the tool itself

This runs other people's code through scanners, so its own hardening matters:

* **No shell.** Every external command goes through one `run_command` choke
  point: list-args, `shell=False`, always a timeout. No user input is ever
  interpolated into a shell.
* **Zip Slip / Zip Bomb protection.** Archive members that escape the
  destination are rejected; uncompressed size and file-count are capped.
* **Git clone is bounded.** Only `http`/`https` schemes, no interactive
  credential/host-key prompts, depth-1, timed out.
* **Secrets are masked.** Gitleaks matches are redacted before they reach the
  API/UI, so the report never re-leaks a secret.
* **Isolated workspaces.** Each scan runs in its own directory, cleaned up
  afterwards.

## Configuration

All optional, via environment variables (see `.env.example`): workspace dir,
per-tool timeouts, upload/extraction limits, `SAST_ALLOW_LOCAL_PATH`, allowed
git schemes, and `SAST_SEMGREP_RULES` (`auto` needs network; point at a local
ruleset for offline scanning).

## Development

```bash
pip install -r requirements.txt pytest
pytest -q          # 17 tests, run without any scanner installed
```

Tests fake the subprocess layer and exercise the pure parsers directly, so the
suite is fast and hermetic. The API tests spin up the real app.

## Project docs

`CoreMain.md` (project north star), `待修改.md` (current plan / gate status)
and `lessons.md` (round summaries) track the secure-SDLC process that produced
this project.
