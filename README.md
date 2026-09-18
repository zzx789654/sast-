# SAST Studio

> [中文說明 (Chinese README)](README.zh.md)

One web page, six free security scanners. Point it at some code and it runs
**Semgrep**, **Bearer**, **Trivy**, **npm audit**, **OSV-Scanner** and
**Gitleaks**, then shows every finding in one severity-sorted report — no
installing each tool, memorising its flags, or reading six different output
formats. Every tool is free to use (no paid licenses required).

| Tool | What it does | Type |
|------|--------------|------|
| **Semgrep** | Pattern-based static analysis (Python engine) | SAST |
| **Bearer** | Semantic/dataflow SAST for security & privacy | SAST |
| **Trivy** | Deps + secrets + IaC misconfiguration | SCA / Secret / IaC |
| **npm audit** | Node dependency advisories (npm registry) | SCA |
| **OSV-Scanner** | Multi-ecosystem deps vs. OSV.dev | SCA |
| **Gitleaks** | Hardcoded secret detection | Secret |

> **Why no CodeQL?** Its CLI is only free for open-source/research use and
> requires a paid GitHub Advanced Security license to scan proprietary code.
> **Bearer** (semantic SAST) and **Trivy** (which also adds IaC misconfig
> scanning) replace it at zero cost. All six tools here are free.

## How it's built

```
Browser ──► nginx (reverse proxy) ──► FastAPI ──► Orchestrator ──► 6 Adapters ──► tools
             :8080  →  :8000          REST API     (job manager)    (one per tool)
```

* **nginx reverse proxy.** In the Docker setup nginx is the public entry point
  (`:8080`) and forwards to the FastAPI backend over the internal network; the
  backend port is never published to the host. nginx sets `X-Forwarded-*`
  headers, raises `client_max_body_size` to match the upload limit, and
  extends proxy timeouts for slow scans. Config: `nginx/nginx.conf`.
* **Adapter pattern.** Each tool has one adapter that does exactly three
  things: *detect availability*, *run*, *normalize output* into a shared
  `Finding` schema. The orchestrator never knows any tool's native format.
* **Graceful degradation.** A tool that isn't installed is reported as
  `unavailable` with an install hint — the scan still runs every other tool.
  So the app is useful whether you have all six tools or none.
* **Project inventory + language 防呆.** Each scan reports the project's file
  count, size and language mix. Every tool declares the languages/inputs it
  needs; for a local path you can *inspect* before scanning to see which tools
  won't apply (and why), and picking an inapplicable tool is flagged. (We show
  an honest inventory rather than fake per-file progress — the tools are batch
  scanners with no reliable per-file progress stream, and the SCA tools work on
  lockfiles, not files.)
* **Simple by design.** In-memory job store, HTTP polling for progress, a
  no-framework vanilla-JS front end. No database, no build step.

## Quick start

### Option A — one command (recommended)

`setup.sh` installs everything (system prerequisites, a Python virtualenv with
all dependencies, and all six scanners), verifies the build by running the test
suite, and tells you how to start. In Docker mode it also installs Docker Engine
and the Compose plugin on Ubuntu when they are missing:

```bash
./setup.sh              # full local setup: venv + deps + scanners + verify
./setup.sh --run        # ...and start the server on http://localhost:8000
```

Other flags: `./setup.sh --docker` (install Docker if needed, then build & start
via Docker Compose),
`--no-tools` (Python app only — scanners degrade gracefully), `--no-venv`
(install into the current environment), `--help`.

If the network is slow while downloading Python packages, increase the retry
window without editing the files:

```bash
PIP_TIMEOUT=1800 PIP_RETRIES=20 ./setup.sh --docker
```

### Option B — Docker (free on Linux servers)

Docker Engine + Compose are free (Apache-2.0); only the Docker **Desktop** GUI
carries a fee for large orgs, and a server deployment doesn't need it.

```bash
docker compose up --build
# open http://localhost:8080   (nginx -> FastAPI backend)
```

This starts two services: **nginx** (public, port 8080) reverse-proxying to
the **backend** (internal). The backend image bundles all six scanners
(Semgrep, Bearer, Trivy, npm audit, OSV-Scanner, Gitleaks) — every one free to
use. To serve on the standard HTTP port, change the nginx mapping to `80:80`
in `docker-compose.yml`.

### Option C — manual local install

```bash
pip install -r requirements.txt
bash scripts/install-tools.sh        # best-effort install of the scanners
uvicorn app.main:app --reload        # http://localhost:8000
```

Any tool you don't install simply shows as unavailable.

## Using it

1. Pick a source: **upload a `.zip`**, paste a **Git URL**, or give a
   **server-local path**.
2. Tick the tools to run (unavailable ones are disabled). Each tool shows what
   it needs; for a local path you can **inspect** first to see the file/language
   inventory and which tools won't apply.
3. **Start scan.**
   - For a **local path** the scan runs immediately (you could already inspect it).
   - For an **upload or Git URL** the source is fetched and inventoried first,
     then the scan **pauses for confirmation**: you review the file/language
     inventory and any inapplicable-tool warnings, then click **Run scan** (or
     **Cancel**, which discards the prepared workspace).
4. Progress updates live per tool (a progress bar plus a spinner and elapsed
   time on each running tool); findings appear as each tool finishes.
5. Read the combined report: a severity summary (critical → info), a per-tool
   row (findings count / duration, or `unavailable` / `not applicable` with the
   reason), and one card per finding with its severity, tool, file:line, and any
   CWE/OWASP tags. Filter by severity, tool, or file name.

   Each card also pinpoints the problem itself. A code finding shows the
   offending source line(s) the scanner reported, next to the line number. A
   dependency finding names the package, the installed version and the version
   that fixes it (or says no fix is available). Secret findings show a masked
   preview only — the secret value is never sent to the browser.
6. Switch the interface between **中文 / English** with the toggle in the top-
   right corner (your choice is remembered).

> A finding's message comes from the scanning tool itself, so it appears in that
> tool's own wording (usually English); the UI adds a localized severity note
> alongside it.

### Tabs

* **Scan** — pick a target, the tools and the policy, then start a scan.
* **Reports** — scan history on the left, the selected report on the right,
  with a severity breakdown bar, CSV export and PDF export (the browser's own
  print-to-PDF, styled for print).
* **Monitor** — scanner versions plus Docker container performance and a
  capacity verdict (see below).

### Scan policy templates

Before starting a scan, choose a built-in policy template. The selected policy
is copied into the job and its verdict is shown with the results.

A policy is judged on the **combined findings of every tool you selected** — no
rule belongs to one particular tool, and the panel lists which tools can report
each kind of finding. The verdict labels the scan; it does not stop the scan or
block a deployment, because the tools have already finished by the time the
policy runs.

* **Standard**: a Critical finding or a leaked secret fails the scan; a High
  finding needs a reviewer. Retention target 30 days.
* **Strict**: the same verdicts as Standard, and additionally declares that a
  scan is required before every pull request and release. Retention 90 days.
* **Report-only**: every scan passes and findings are only listed — useful for
  an initial baseline. Retention 7 days.

The six policy rules are independent fields: Critical blocking, High manual
review, secret blocking, false-positive exception metadata (owner/reason/expiry),
report retention, and required PR/release scans. Each rule can be adjusted after
picking a template, and the scan runs under the rules you set.

A **manual review** decision needs a reviewer name and a note before it can be
approved or rejected. A **blocked** decision can be cleared by recording a
time-limited false-positive exception (owner and reason required) against a
specific finding; once the exception expires, that finding counts again.

### Docker capacity (Monitor tab)

Raw CPU and memory percentages do not answer "is this container big enough?",
so each running container also gets a verdict:

* **Memory** is judged against its limit, because hitting the limit is what
  gets a scan OOM-killed. A limit equal to host memory means no limit was set,
  which is flagged too: the container can then starve the host.
* **CPU** is reported for load and flagged only when the quota actually
  throttles it — a busy scanner using its cores is normal, just slower.
* A failed allocation (OOM) or an observed throttle outranks any percentage,
  since those are evidence rather than a prediction.

Check the tab while a scan is running: that is when a container is under load.

The application records retention and PR/release requirements in the policy
metadata. Enforcing repository retention and GitHub PR/release checks still
requires a persistent report store and CI/GitHub integration; the current
repository does not provide those external services.

### REST API

The UI is a thin client over a small JSON API — handy for scripting/CI:

| Method & path | Purpose |
|---|---|
| `GET /api/tools` | tool availability + what each tool needs |
| `GET /api/policies` | policy rules and built-in templates |
| `POST /api/inspect` | inventory a local path + per-tool applicability |
| `POST /api/scans` | start a scan (`source_kind`=`upload`/`git`/`path`, `tools`, …) |
| `GET /api/scans/{id}` | scan status, progress, results |
| `GET /api/scans/{id}/export.csv` | download that scan's findings as CSV |
| `POST /api/scans/{id}/review` | approve or reject a High-finding policy review |
| `POST /api/scans/{id}/exceptions` | add a time-limited false-positive exception |
| `POST /api/scans/{id}/confirm` \| `/cancel` | run or discard a scan awaiting confirmation |
| `GET /api/health` | health check |

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

## Keeping the scanners up to date

- **Vulnerability data updates itself.** Trivy pulls its DB, OSV-Scanner queries
  OSV.dev and npm audit queries the npm registry at scan time, so CVE/advisory
  freshness is automatic — only the tool *binaries* need version management.
- **Binaries are version-pinned** in `scripts/install-tools.sh` and the
  `Dockerfile` (Trivy/OSV/Gitleaks) so builds are reproducible. Bump those
  versions deliberately; automate the bumps with Renovate/Dependabot if you like.
- **Update in place** with `./setup.sh --update` (updates Semgrep via pip and
  re-installs the pinned binaries), or rebuild the Docker image.
- **See what's installed** any time in the **Monitor** tab or at `GET /api/tools`.

## Monitoring

The **Monitor** tab shows each scanner's installed version and, optionally,
live per-container performance (CPU / memory / network) for the Docker
deployment. Container stats are **off by default** because reading them needs
the Docker daemon socket mounted into the container — a privileged capability.
To enable on a trusted deployment, set `SAST_ENABLE_DOCKER_STATS=true` and mount
the socket read-only (both are commented in `docker-compose.yml`):

```yaml
    environment:
      SAST_ENABLE_DOCKER_STATS: "true"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

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
