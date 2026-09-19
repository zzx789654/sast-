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

* **Scan** — pick a target and the tools, then start a scan.
* **Reports** — scan history on the left, the selected report on the right,
  with a severity breakdown bar, CSV export and PDF export (the browser's own
  print-to-PDF, styled for print).
* **Monitor** — scanner versions plus Docker container performance and a
  capacity verdict (see below).

### How a scan is judged

There is one fixed rule. There is nothing to configure before a scan, and the
rule is stated above the scan button rather than hidden in a settings panel.

| What any tool found | Verdict |
|---|---|
| Critical or High severity | **must not go live** |
| A leaked secret, at any severity | **must not go live** |
| Medium severity | **needs a reviewer** |
| Low, informational, or nothing | **passes** |

Two things about this rule are easy to misread, so they are worth stating
plainly:

* It applies to the **combined findings of every tool that ran**. No rule
  belongs to one particular tool: a High from `npm audit` blocks exactly as a
  High from `semgrep` does.
* The verdict **labels the scan**. It does not stop a build or a deployment —
  every tool has already finished by the time the verdict is computed, and
  nothing downstream consumes it. Wiring it into CI is a separate job.

A **needs a reviewer** verdict requires a reviewer name and a note before it can
be approved or rejected. A **must not go live** verdict has no override in the
application: fix the finding and scan again.

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

### REST API

The UI is a thin client over a small JSON API — handy for scripting/CI:

| Method & path | Purpose |
|---|---|
| `GET /api/tools` | tool availability + what each tool needs |
| `GET /api/policies` | the fixed rule used to judge a scan |
| `POST /api/inspect` | inventory a local path + per-tool applicability |
| `POST /api/scans` | start a scan (`source_kind`=`upload`/`git`/`path`, `tools`, …) |
| `GET /api/scans/{id}` | scan status, progress, results |
| `GET /api/scans/{id}/export.csv` | download that scan's findings as CSV |
| `POST /api/scans/{id}/review` | approve or reject a scan awaiting review |
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
git schemes, and `SAST_SEMGREP_RULES` (defaults to `p/default`, which needs
network; point at a local ruleset for offline scanning). Do not set it to
`auto` — semgrep rejects that config because scans always run with
`--metrics=off`, so no code data leaves the host.

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

The **Monitor** tab shows each scanner's installed version, live per-container
performance (CPU / memory / network) for the Docker deployment, and the
maintenance actions below.

`docker-compose.yml` enables container stats by default. Reading them needs the
Docker daemon socket mounted into the container, which is a privileged
capability even read-only, so the listing is scoped by label to this compose
project rather than every container on the host. Turn it off with
`SAST_ENABLE_DOCKER_STATS=false` and remove the socket mount.

### Maintenance actions, and who can use them

The Monitor tab can update the scanners that can be updated in place and
restart the application.

> **There is no login in front of these.** This project deliberately has no
> account system, so anyone who can open the page can update the scanners and
> restart the service. Run it on a trusted network only — do not expose port
> 8080 to the internet.

What the code does within that constraint:

- every command is a fixed argument list with `shell=False`, and the tool names
  are checked against the built-in list, so a request cannot inject a command;
- one maintenance job runs at a time, and a restart is limited to one per
  minute so the service cannot be kept bouncing;
- command output is scrubbed of credentials and absolute paths before it is
  shown, because that log is readable by anyone who can reach the page.

Restarting clears scan history, which is held in memory by design.

If you need defence in depth without adding accounts, restrict `/api/admin/`
at the reverse proxy — for example in `nginx/nginx.conf`:

```nginx
location /api/admin/ {
    allow 192.168.0.0/16;   # your management network
    deny all;
    proxy_pass http://sast-studio:8000;
}
```

Scanners pinned as binaries in the image (Bearer, Gitleaks, OSV-Scanner, npm)
cannot be changed from the page; bump the version in the `Dockerfile` and
rebuild. The panel says which is which.

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
