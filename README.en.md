# SAST Studio

> **[繁體中文完整說明 (full Traditional Chinese README)](README.md)** — screenshots, the data each
> scanner sends off the host, step-by-step deploy/update scripts, and the complete API reference.

![Scan report: severity breakdown, per-tool results and verdict](docs/images/report.png)

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

Start by getting the code:

```bash
git clone https://github.com/zzx789654/sast-.git
cd sast-
```

### Which command do I run?

| Situation | Command |
|---|---|
| **First time**, Docker not installed yet | `./setup.sh --docker` |
| **First time**, Docker already installed | `./scripts/deploy.sh` |
| **Updating** the scanners (and the app) | `./setup.sh --update` |
| Deploying a code change, scanners unchanged | `./scripts/deploy.sh` |
| Running without Docker, on the host | `./setup.sh` then `./setup.sh --run` |

The two you will use after the first day:

```bash
./setup.sh --update      # update everything: cache downloads, rebuild, switch over
./scripts/deploy.sh      # deploy a code change: build and switch over
```

Both are safe to re-run, both keep the old image so you can roll back, and
**neither touches your accounts or custom rules** — those live on named
Docker volumes that survive a rebuild. You never need to reset a password
to update. (Scan history is the exception: it is held in memory and is
cleared when the container restarts.)

The rest of this section explains each route. If you just want it running on
a fresh Ubuntu server: `./setup.sh --docker`.

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
* **Settings -> Log** — one activity log covering scans, sign-ins, service
  and container state, and API/MCP calls, with filters and a retention
  setting in days (see below).

### Judging a finding

A scanner reports a *pattern*. Whether that pattern is a problem *here* is a
judgement it cannot make, so some findings will be wrong. That is normal, and
a tool that never reported a false positive would be missing real bugs.

Scanning this project with itself is a good illustration: the single Critical
it reported was `subprocess.run` in `app/adapters/base.py` — the one function
in the codebase whose entire purpose is to make command execution safe. The
pattern (a variable reaching a subprocess call) is real. The vulnerability is
not: the argument is a fixed list, `shell=False`, and the tool name has already
been checked against a whitelist.

Three questions settle most findings:

1. **Look at the code on the card.** Every finding shows the lines it matched.
   If the flagged value is a constant, or already validated above, the pattern
   matched but the bug is not there.
2. **Can the input actually reach it?** "Unsanitized input" assumes the value
   comes from outside. If it comes from your own code, the premise is wrong.
3. **Is the protection somewhere the scanner cannot see?** Validation in a
   caller, a framework, or a proxy is invisible to a tool reading one file.

Then mark it. Each finding has **real issue / false positive / accepted risk**.
The mark is kept per finding, survives a rescan, and prints into the PDF — so
whoever reads the report sees your judgement rather than raw output.

Marks are stored in your browser. They are notes for a reader, not an audit
trail: this application has no login, so it cannot record *who* decided what,
and storing a name that nobody verified would be worse than storing nothing.
If you need sign-off with accountability, export the PDF and handle it in a
system that has accounts.

**Never mark something a false positive because you do not understand it.**
"I read the code and the input cannot get there" is a judgement. "This looks
complicated" is not.

### Custom rules

The Scan tab has an editor for writing your own checks in **Semgrep (YAML)** or
**Trivy (Rego)**. Built-in templates are worked examples that already run; edit
one, give it a name and save it as your own. Templates themselves cannot be
overwritten.

Saving runs the rule past the scanner first, so a rule that does not compile is
never stored -- the error appears next to the editor rather than during a scan
days later.

Saving a rule and using it are separate steps. Tick a rule in **Custom rules to
apply** and it joins that scan. Custom rules **add to** the default ruleset
rather than replacing it, so writing one of your own does not cost you the
coverage of `p/default`.

Trivy checks are written in Rego, which is a real language, and Trivy
evaluates it with OPA's full built-in set. A rule calling `http.send` really
does make a request from inside the container -- verified on this deployment.
Because the editor has no login, custom checks may not call `http.send`,
`net.lookup_ip_addr`, `opa.runtime`, `rego.parse_module` or `trace`; a check
should only inspect the project being scanned. The restriction is applied
before the rule runs, including when you press Check rule.

Rules are copied into each scan's workspace when it starts, so editing a rule
while a scan is running cannot change what that scan is executing.

They are stored on the Docker volume (`SAST_RULES_DIR`, `/data/rules` in the
compose file), so they survive a restart and an image rebuild. They are not in
version control: they are yours, not the project's.

Only Semgrep and Trivy take custom rules. Bearer and Gitleaks have their own
rule formats but are not wired up here; npm audit and OSV-Scanner have no rule
language at all -- they look packages up in a vulnerability database, so there
is nothing to write.

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

Neither verdict can be changed from the application. **Needs a reviewer** is a
label for whoever signs the report off -- export the PDF and send it on. **Must
not go live** means fix the finding and scan again. Signing off in a page with
no login, whose history lives in memory, would not have been worth the paper it
was printed on.

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
| `GET /api/rules` | custom rules and built-in templates |
| `GET /api/rules/{engine}/{name}` | one rule's content |
| `POST /api/rules/validate` | check a rule compiles, without saving |
| `POST /api/rules/{engine}/{name}` | save a rule (validated first) |
| `DELETE /api/rules/{engine}/{name}` | delete a rule |
| `POST /api/inspect` | inventory a local path + per-tool applicability |
| `POST /api/scans` | start a scan (`source_kind`=`upload`/`git`/`path`, `tools`, …) |
| `GET /api/scans/{id}` | scan status, progress, results |
| `GET /api/scans/{id}/export.csv` | download that scan's findings as CSV |
| `GET/POST /api/triage` | read or set a finding's mark (`real` / `false_positive` / `accepted`) |
| `POST /api/scans/{id}/reevaluate` | re-judge a scan against the current marks |
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
git schemes, `SAST_SEMGREP_RULESETS` (comma separated; defaults to
`p/default,p/owasp-top-ten`, and the scan form lets you tick others), and
`SAST_SEMGREP_RULES` (defaults to `p/default`, which needs
network; point at a local ruleset for offline scanning). Do not set it to
`auto` — semgrep rejects that config because scans always run with
`--metrics=off`, so no code data leaves the host.

## Accounts and the API

The deployment requires a sign-in. On the first start it creates an
administrator and prints the password to the log once -- `scripts/deploy.sh`
surfaces it at the end of a first deploy. It is not stored in a readable form,
so save it then and change it from **Settings**. Set `SAST_ADMIN_USER` and
`SAST_ADMIN_PASSWORD` to choose them instead, or `SAST_REQUIRE_AUTH=false` to
run without accounts at all.

Passwords are hashed with scrypt from the standard library -- memory-hard, so
a stolen database is expensive to attack -- and the parameters are stored with
each hash, so the cost can be raised later without breaking existing accounts.

Two roles only: administrator and user. An administrator manages accounts; the
last one cannot be deleted, disabled or demoted, because that click would lock
everybody out.

### A fuller package list, with licences

`osv-scanner` can report every package and its licence, not just the ones
with an advisory -- including transitive dependencies, and from a
`requirements.txt` of version ranges that trivy reads nothing from. On this
project that is 18 packages with licences against trivy's 0.

It is off by default, and it is a **per-scan tick box** on the scan form --
"Full package list with licences" -- because the answer differs between
your own code and a client's.

To turn it on for every scan on a deployment:

```bash
SAST_OSV_FULL_INVENTORY=true    # in .env, then ./setup.sh --update
```

The reason it is opt-in, stated precisely:

| | |
|---|---|
| **Sent** | package names and version constraints (`fastapi`, `>=0.111`) |
| **Sent to** | `api.deps.dev` — osv-scanner's default data source, run by Google |
| **Not sent** | source code, file contents, file names, secrets, scan findings |
| **Size** | ~88 KB per scan, measured |

Measured rather than assumed: the same project resolves 12 packages online
and 1 with `--offline`, and the difference is entirely what deps.dev
resolved from the range. That is fine for your own code and not obviously
fine for a client's, so the scan does not do it unless asked.

### Packages and licences

Every scan also lists what the project pulls in and, where it can, under
which licence. It is collapsed under the findings, and exports separately:

```
GET /api/scans/<id>/packages.csv
```

The honest limitation: a lockfile records names and versions, not licences.
The licence is read from the package's own files, so it is known only when
the packages are actually installed (`node_modules`, `site-packages`). On a
plain repository checkout the normal result is a complete package list with
the licences unknown -- which is reported as "unknown" rather than guessed
from the package name.

When a manifest only gives version ranges (`fastapi>=0.111`), no scanner
can say which release is installed, so the panel falls back to listing the
dependencies the project **declares** -- read straight from
`requirements.txt`, `package.json`, `pyproject.toml` or `go.mod`. That list
names the libraries but excludes transitive dependencies and carries no
licences, and the panel says so rather than letting a short list look
complete.

Packages under copyleft or commercial-use terms are listed first and marked.
That is a prompt to look, not a verdict, and it is not legal advice.

### Marking a finding, and what it does to the verdict

A finding can be marked **real**, **false positive** or **accepted**. The
last two mean "this will not be fixed", so the finding stops counting
towards the scan's verdict -- a page of false positives no longer reports
"blocked".

Two things keep that honest. The verdict always reports both numbers, so
"passed, 6 of 7 set aside" never looks like a clean scan. And a **secret is
never dismissible**: a credential that reached the repository is already
exposed, and deciding it is a false positive does not un-expose it. If it
genuinely is not a secret, the fix is a scanner rule, not a verdict
override.

Marks are recorded on the server with the name of whoever made them. They
used to live in the browser, which was right while they were only notes for
the reader; a mark that can clear a Critical finding has to be attributable.

### Container resources (Settings -> Docker resources)

Shows each container's memory and cpu limit, what it is actually using, and
what the host has. All three together, because a limit means nothing alone:
2GB is generous or crippling depending on the other two.

By default nothing is limited, which the panel flags as **no limit ⚠** --
that is the finding, not a blank field. An unlimited container can exhaust
the host rather than only itself, so a runaway scan takes everything down.

Type the limits you want and press **Generate**. You get a compose snippet:

```yaml
services:
  sast-studio:
    deploy:
      resources:
        limits:
          memory: 2g
          cpus: '2.0'
```

Paste it into `docker-compose.yml` and run `./scripts/deploy.sh`.

**It produces a snippet rather than applying the change**, deliberately. The
container can reach `/containers/update` through the mounted socket -- `:ro`
makes the socket file read-only but does not restrict the commands sent over
it (it answers 409, not 403). Using that would give this app write access to
every container on the host, and compose would undo the change on the next
deploy anyway, leaving you wondering where the setting went.

Values are validated server-side: a limit above host capacity, a negative or
non-numeric size, and a service name carrying YAML syntax are all refused.

Administrators only, since it reports host capacity.

### The activity log (Settings -> Log)

One table for everything worth looking back at, because the useful questions
cross categories: *what was running when it restarted?* cannot be answered
from separate lists.

| Category | What lands there |
|---|---|
| **掃描 / Scan** | what was scanned, by whom, from which address, and when |
| **登入 / Login** | sign-ins, successful and failed, with the source address |
| **服務 / Service** | start, stop, restart, retention changes |
| **容器 / Container** | container state changes and capacity pressure |
| **API/MCP** | API-token calls and MCP calls, each with its source IP |

Filter by clicking the category chips (they carry counts), by level
(info / warning / error), or by typing in the search box — it matches the
account, address, target and detail together.

**Retention is in days.** Set it at the bottom of the tab; anything older is
deleted as soon as you save, not at some later sweep. The default is 30 days.
Days rather than a row count on purpose: a rolling window of N rows sounds
bounded until a busy afternoon of API calls pushes out last week's failed
logins, which is the record you actually wanted.

Two things are deliberately *not* logged row-for-row:

- **Container state** is sampled every 60 seconds in the background and only
  transitions are recorded. The sampler runs whether or not anyone has the
  Monitor tab open — otherwise a crash at 3am would leave no trace.
- **API rows** cover token and MCP calls, not browser traffic. A browser
  session already produces a sign-in row, and logging its every fetch would
  bury the machine-to-machine calls that are the reason to look.

Administrators see every account's rows and can change retention. Everyone
else sees only their own: the log names who scanned what and which address
called the API, which is an account's activity rather than shared
information.

### Login throttling and token expiry

Both are off-ish by default and live in **Settings -> Account -> password
rules**:

- **Failed logins** lock an account after `max_attempts` (10) for
  `lockout_minutes` (15). Counted per username *and* per source address, so
  spraying many usernames from one place is caught too, and one account
  being attacked cannot lock out everybody else. A successful sign-in clears
  the count. Set `max_attempts` to 0 to disable.
- **API tokens** expire after `token_days` (0 = never, the previous
  behaviour). An expired token is refused exactly like a revoked one.

### Telling the deployment its own address

The MCP client entry and the `.env` template both say where a tool should
send its bearer token. Deriving that from the `Host` header would let whoever
sets the header choose the destination, so set the address explicitly:

```bash
SAST_PUBLIC_URL=https://sast.example.com
```

Without it, the host is taken from the request but only if it is in
`SAST_ALLOWED_HOSTS` (comma separated); anything else falls back rather than
being echoed into a file somebody will paste into a client.

### When a password expires

`SAST_...` nothing: expiry is a policy setting, in **Settings -> Account ->
password rules**, off by default (`0` days). When it is on and a password
passes that age, the account can still sign in but can do nothing else --
every other endpoint answers `403` with `reason: password_expired`, and API
tokens for that account stop working too, since a token speaks for the
account.

The way back is on the login page itself: signing in with the expired
password offers a change-password form there, because the settings page is
exactly what an expired account may not reach. The current password is still
required, so this is not a way in.

An administrator can also reset it from **Settings -> User management**, and
`scripts/reset-password.sh` works regardless of expiry.

### Forgotten password

There is no reset link on the login page: sending one needs mail this
deployment does not have, and a self-service reset is a second way in to
every account. Recovery runs from the host instead, where shell access is
already more than the login grants.

```bash
./scripts/reset-password.sh                  # reset admin, prompted twice
./scripts/reset-password.sh alice            # reset a named account
./scripts/reset-password.sh admin --generate # make one up and print it once
./scripts/reset-password.sh --list           # which accounts exist
```

It finds the running container by itself, or falls back to a local checkout.
The password is typed at a prompt or generated -- never passed as an
argument, which would put it in `ps` output and shell history.

The password rules still apply, with one exception: the "do not reuse an old
password" rule is relaxed, because refusing every password the account
remembers can leave a locked-out administrator with no way back in. A reset
also revokes that account's sessions and API tokens, on the assumption that a
password being reset may be a password that leaked, and re-enables the
account if it was disabled.

### API tokens

**Settings** issues tokens for calling the API from a script or an assistant.
A token belongs to the person who created it, so whatever it does is their
doing -- and disabling that account disables its tokens with it. The secret is
shown once at creation; only a hash is kept.

```bash
curl -H "Authorization: Bearer sast_..." http://your-host:8080/api/tools
```

### MCP

The same token gives an AI assistant three tools over
[MCP](https://modelcontextprotocol.io): `scan_git_repository`,
`get_scan_result` and `list_scanners`. The endpoint is `POST /mcp`, Streamable
HTTP, JSON responses -- a scan is a request and an answer, so there is nothing
for an event stream to carry.

```json
{
  "mcpServers": {
    "sast-studio": {
      "url": "http://your-host:8080/mcp",
      "headers": { "Authorization": "Bearer sast_..." }
    }
  }
}
```

A scan started this way is attributed to the token's owner and appears in the
Reports tab like any other. Findings carry the matched code, because a scanner
reports a pattern and an assistant needs the same evidence a person does to
judge whether it matters.

The endpoint validates `Origin`, which is what stops a web page driving it from
someone's browser (DNS rebinding). Same-host is allowed automatically; set
`SAST_MCP_ORIGINS` for anything else.

## Keeping the scanners up to date

### The two commands

```bash
./setup.sh --update      # update the scanners, then rebuild and switch over
./scripts/deploy.sh      # deploy the current source: build and switch over
```

They overlap deliberately — `--update` calls `deploy.sh` to finish the job —
but they answer different questions:

| | `./setup.sh --update` | `./scripts/deploy.sh` |
|---|---|---|
| Installs Docker if missing | no | no (use `./setup.sh --docker`) |
| Refreshes scanner binaries | **yes** | no, uses whatever the image pins |
| Downloads into `./vendor` first | yes | yes |
| Pulls the latest source | yes (via deploy.sh) | yes |
| Rebuilds the image | yes | yes |
| Switches the container | yes | yes |
| Keeps a rollback image | yes | yes |
| Waits for a healthy check | yes | yes |

So: **`--update` when you want newer scanners, `deploy.sh` when you have
changed code.** If you are not sure, `--update` is the safe choice; it does
strictly more.

### What `--update` does, step by step

On a deployment where Docker is serving the app:

1. **Cache the downloads** into `./vendor` (`scripts/fetch-vendor.sh`).
   Resumable, checksum-verified, and it skips anything already there — so a
   second run costs no network at all.
2. **Skip the host install.** The scanners that run are the ones inside the
   image, so installing copies onto the host would be several minutes spent
   on binaries nothing executes.
3. **Rebuild and switch** (`scripts/deploy.sh`): pull the source, build the
   new image while the old container keeps serving, switch over, wait for
   the health check, and keep the previous image tagged for rollback.

On a host install (no container running) it installs the scanners onto the
host instead and stops there, because there is nothing to rebuild.

Two escape hatches, for when you want only part of it:

```bash
SKIP_DEPLOY=1 ./setup.sh --update    # refresh the downloads, do not rebuild
SKIP_VENDOR=1 ./setup.sh --update    # rebuild, do not touch the cache
```

### What an update does not touch

Accounts, custom rules and workspaces are on named Docker volumes
(`sast-accounts`, `sast-rules`, `sast-workspaces`), which a rebuild does not
recreate. **Updating never costs you a password, a rule or a login.** Scan
history is deliberately different: it is held in memory and does not survive
a restart.

### If something goes wrong

The old image is tagged before every deploy, so going back is one command:

```bash
./scripts/deploy.sh --rollback
```

The build runs while the old container keeps serving, so a failed build
changes nothing — the failure message says so rather than leaving you to
guess. A deploy that fails the health check tells you to roll back rather
than leaving a broken container in place.



Only two of the six can be updated from the Monitor tab, and the reason is
how they are installed rather than a shortcut:

| tool | updates in place? | why |
|---|---|---|
| semgrep | yes | a pip package, so `pip install --upgrade` works |
| trivy | its database | the binary is pinned; `--download-db-only` refreshes the part that changes daily |
| bearer, gitleaks, osv-scanner | no | pinned binaries in `/usr/local/bin`, which the app's account cannot write, and none of them has a self-update command |
| npm_audit | no | npm's global install needs root, and the advisories come from the registry at scan time anyway |

For the four that cannot, **Check versions** asks GitHub for the newest
release of each and says whether the pinned one is behind. Changing it means
editing the `ARG`s at the top of the `Dockerfile` (and the matching defaults
in `scripts/fetch-vendor.sh`) and rebuilding -- which is the point of pinning
them: the version that ships is one somebody chose and checksummed.



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
