<div align="center">

# 🛡️ container-audit

**Read-only security audit for Docker hosts.**

Point it at your containers and it reports the risky configuration — root users, exposed ports,
secrets in environment variables, privileged mode, dangerous capabilities, mounted Docker sockets,
shared host namespaces, outdated images and missing hardening — as a clean text, JSON or Markdown report.

[![CI](https://github.com/petrhromadka/container-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/petrhromadka/container-audit/actions/workflows/ci.yml)
![defensive](https://img.shields.io/badge/purpose-defensive-blue)
![read-only](https://img.shields.io/badge/access-read--only-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-informational)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

[Quick start](#-quick-start) · [What it checks](#-what-it-checks) · [Usage](#-usage) · [How it works](#-how-it-works) · [Safety](#-safety)

</div>

> [!NOTE]
> **Defensive and read-only.** container-audit only runs `docker ps` and `docker inspect` (or reads
> a saved copy of that JSON). It never starts, stops, or modifies a container, and it never sends
> data anywhere.

---

## 🚀 Quick start

No Docker needed to try it — the repo ships a sample `docker inspect` dump:

```bash
git clone https://github.com/petrhromadka/container-audit
cd container-audit
uv run container-audit --input tests/fixtures/sample_inspect.json
```

You'll see eleven findings on the intentionally-insecure `bad-db` container and a clean bill of health
for the hardened `good-web` one. To scan your own host instead, just run `container-audit` — it
reads live containers via `docker ps` / `docker inspect`.

---

## 🔍 What it checks

Severity key: 🔴 critical · 🟠 high · 🟡 medium · 🔵 low. Each finding carries a title, a plain-language
explanation, short **redacted** evidence, and a one-line remediation.

### Privilege &amp; escape

| | Check id | What | Why it matters |
| :-: | --- | --- | --- |
| 🔴 | `docker-socket-mount` | `/var/run/docker.sock` is mounted in | Socket access is effectively root on the host: it can start any other container. |
| 🔴 | `privileged` | Container runs `--privileged` | Disables most isolation: full device access and all capabilities. |
| 🟠 | `root-user` | Runs as root (no `USER`, or `0`/`root`) | A process escape or file-permission bug has root inside the container. |
| 🟠 | `dangerous-caps` | Caps like `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE` added | Common container-escape building blocks. |
| 🟠 | `sensitive-host-mount` | Host paths (`/`, `/etc`, `/proc`, `/root`, …) bind-mounted | A compromised container can read or alter host config and credentials. |

### Namespaces &amp; exposure

| | Check id | What | Why it matters |
| :-: | --- | --- | --- |
| 🟠 | `host-pid` | Shares the host PID namespace (`--pid=host`) | It can see and signal every process on the host. |
| 🟠 | `host-network` | Shares the host network namespace (`--network=host`) | Network isolation and port mapping are bypassed. |
| 🟡 | `port-all-interfaces` | Port published on `0.0.0.0` / `::` | Reachable from every network the host is on, not just where you intend. |
| 🟡 | `host-ipc` | Shares the host IPC namespace (`--ipc=host`) | Shared memory and semaphores cross the container boundary. |
| 🔵 | `host-uts` | Shares the host UTS namespace (`--uts=host`) | It can change the host's hostname. |

### Secrets &amp; hardening

| | Check id | What | Why it matters |
| :-: | --- | --- | --- |
| 🟠 | `secret-in-env` | Env var that looks like a secret, or a URL with embedded credentials | Secrets in env vars leak via `docker inspect`, logs and child processes. |
| 🟡 | `no-new-privileges-missing` | `no-new-privileges:true` is not set | setuid binaries inside the container can still escalate privileges. |
| 🔵 | `writable-rootfs` | Root filesystem is writable (not `read_only`) | An attacker can persist changes and tooling. |
| 🟡 | `stale-image` | Image was built more than 180 days ago | Old images usually miss security patches released since; rebuild or pull a current one. |
| 🔵 | `unpinned-image` | Image uses `:latest`, no tag, or no digest | Pulls aren't reproducible; upstream can silently change what runs. |
| 🔵 | `unlimited-memory` | No memory limit set | A single container can exhaust host RAM and take the host down. |

---

## 📦 Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). The `docker` CLI is only needed to audit
a live host; auditing a saved file with `--input` does not need it.

```bash
uv tool install .                 # install as a tool from a checkout
uvx --from . container-audit      # or run without installing
uv run container-audit            # or run inside the project environment
uv run python -m ca               # module form (use this if the console script is blocked)
```

> On Windows, Smart App Control may block the generated `container-audit.exe` launcher. Run the
> tool as a module instead: `python -m ca` (or `uv run python -m ca`).

Once published to PyPI it also installs with `pipx install container-audit` or `uvx container-audit`.

### Run with Docker

The image ships the tool (the Docker CLI is intentionally not bundled); feed it a saved inspect dump
on stdin:

```bash
docker build -t container-audit .
docker inspect $(docker ps -aq) $(docker inspect -f '{{.Image}}' $(docker ps -aq) | sort -u) | docker run --rm -i container-audit --input /dev/stdin --fail-on high
```

---

## 💻 Usage

```bash
container-audit                                             # audit running containers
container-audit --include-stopped                          # include stopped ones too
container-audit --format json                              # machine-readable output
container-audit --format markdown > report.md              # for an issue / PR / wiki

docker inspect $(docker ps -aq) $(docker inspect -f '{{.Image}}' $(docker ps -aq) | sort -u) > sample.json  # save containers + their images
container-audit --input sample.json --fail-on high         # audit the dump; non-zero exit for CI
```

| Flag | Meaning |
| --- | --- |
| `--input FILE` | Read `docker inspect` JSON from `FILE` instead of calling Docker. |
| `--format FORMAT` | Output format: `text` (default), `json` or `markdown`. |
| `--include-stopped` | Also inspect containers that are not running. |
| `--include-host` | Include the real hostname in the report (off by default, so output is safe to share). |
| `--min-severity LEVEL` | Hide findings below `LEVEL` (`info`, `low`, `medium`, `high`, `critical`). Default `info` (show all). |
| `--fail-on LEVEL` | Exit non-zero if any shown finding is at or above `LEVEL` (`none`, `low`, `medium`, `high`, `critical`). Default `none`. |
| `--version` | Print the version and exit. |

**Exit codes:** `0` clean (nothing reached `--fail-on`) · `1` a finding met `--fail-on` · `2` could
not run (Docker unavailable, or a missing/invalid `--input` file).

Image age comes from `docker inspect --type image`. If an image was deleted while its container
still runs, or the dump has no image objects, the age is unknown and `stale-image` skips that
container. Images from reproducible builds (distroless, ko, Nix) carry a fixed 1970 date and are
skipped too.

### Coolify and other self-hosted PaaS

It works unchanged on a [Coolify](https://coolify.io) host. Expect `docker-socket-mount` on Coolify's
own `coolify-proxy` (Traefik) and `coolify-sentinel` containers: they need the socket by design. Review
everything else, especially apps you deployed from public templates, which often publish database
ports on `0.0.0.0` and keep passwords in environment variables.

### Use in CI

```yaml
- name: Audit containers
  run: |
    docker inspect $(docker ps -aq) $(docker inspect -f '{{.Image}}' $(docker ps -aq) | sort -u) > containers.json
    uvx --from git+https://github.com/petrhromadka/container-audit \
      container-audit --input containers.json --fail-on high
```

---

## ⚙️ How it works

```text
docker ps / docker inspect  ->  parse into Container objects  ->  run checks  ->  render report
       (or --input file)                                        (pure functions)   text / json / markdown
```

1. **Collect** — list containers with `docker ps` and read their config with `docker inspect` (or
   parse a saved copy via `--input`).
2. **Check** — each check is a pure function over the parsed containers that yields findings. Checks
   never talk to Docker and never change anything.
3. **Report** — findings are sorted by severity and rendered as text, JSON or Markdown; with
   `--fail-on`, the exit code reflects the worst severity found.

<details>
<summary>📋 Example report (from the bundled sample fixture)</summary>

```text
container-audit report
Host:      (redacted)
Scanned:   2 container(s)
Timestamp: 2026-11-05T19:32:19+00:00
Findings:  11 (critical=2, high=3, medium=4, low=2, info=0)

[CRITICAL] docker-socket-mount  bad-db - Access to the Docker socket grants control of the Docker daemon, and therefore of the host.
    evidence:    /var/run/docker.sock -> /var/run/docker.sock (rw)
    remediation: Remove the socket mount or use a restricted docker-socket-proxy.
[CRITICAL] privileged  bad-db - Privileged mode grants all capabilities and host device access, so a compromise is effectively a host compromise.
    evidence:    HostConfig.Privileged=true
    remediation: Remove `privileged: true`; add only the capabilities needed.
[HIGH] dangerous-caps  bad-db - These capabilities allow administrative or host-affecting operations and weaken container isolation.
    evidence:    cap_add: SYS_ADMIN
    remediation: Remove these from `cap_add`; grant only what is required.
[HIGH] root-user  bad-db - The main process runs as UID 0, widening the impact of an escape.
    evidence:    Config.User=''
    remediation: Set a non-root USER in the image or `user:` in compose.
[HIGH] secret-in-env  bad-db - Environment variable DB_PASSWORD looks like a secret and has a literal value; it is visible via docker inspect and to anyone who can read the container configuration.
    evidence:    DB_PASSWORD=***
    remediation: Use Docker secrets or an env file kept outside the image.
[MEDIUM] host-ipc  bad-db - The container can access host shared memory and IPC objects, weakening isolation.
    evidence:    HostConfig.IpcMode=host
    remediation: Remove `ipc: host`; do not share the host IPC namespace.
[MEDIUM] no-new-privileges-missing  bad-db - Without no-new-privileges, setuid binaries inside the container can escalate privileges.
    evidence:    HostConfig.SecurityOpt lacks no-new-privileges
    remediation: Add `security_opt: ["no-new-privileges:true"]`.
[MEDIUM] port-all-interfaces  bad-db - The port is reachable from every network the host is attached to.
    evidence:    0.0.0.0:5432 -> 5432/tcp
    remediation: Bind to 127.0.0.1 (e.g. 127.0.0.1:<port>:<port>) unless public.
[MEDIUM] stale-image  bad-db - The image is 1390 days old, so it likely lacks security patches released since it was built.
    evidence:    image built 2023-01-15 (1390 days ago)
    remediation: Pull or rebuild the image on a current base and recreate the container; automate updates (e.g. Renovate, Dependabot).
[LOW] unlimited-memory  bad-db - With no memory limit, one container can exhaust the host's RAM.
    evidence:    HostConfig.Memory=0
    remediation: Set a memory limit (`mem_limit` in compose).
[LOW] writable-rootfs  bad-db - A writable root filesystem lets an attacker persist changes.
    evidence:    HostConfig.ReadonlyRootfs=false
    remediation: Set `read_only: true` and use tmpfs or volumes for writable paths.
```

The second container, `good-web`, is hardened (non-root, read-only rootfs, memory limit,
`no-new-privileges`, port bound to `127.0.0.1`) and produces no findings.

</details>

---

## 🔒 Safety

- **Read-only.** The only Docker commands used are `docker ps` and `docker inspect`. Nothing is
  started, stopped, restarted, or reconfigured.
- **Secret values are never printed.** For env vars that look like secrets, only the variable
  **name** is reported, with the value masked to `***` — no characters of the value appear in any
  output format.
- **Hostname hidden by default.** Reports show `(redacted)` as the host unless you pass
  `--include-host`.
- **Output is sanitized.** Control and terminal-escape characters from container metadata are
  stripped, so a report is safe to print in a terminal or paste into Markdown.
- **No network use, no runtime dependencies.** The tool never transmits data anywhere.
- Reports can still reveal your container names, image names, ports and mount paths — review one
  before sharing it publicly.

---

## 🧰 Development

```bash
uv sync                      # create the environment
uv run ruff check .          # lint
uv run ruff format --check . # formatting
uv run ty check src          # type check
uv run pytest                # tests
```

Pre-commit hooks (ruff, gitleaks, whitespace fixes) live in `.pre-commit-config.yaml`; install them
with [`prek`](https://github.com/j178/prek) or `pre-commit`. CI runs the same checks plus a gitleaks
scan over the full history.

To add a check, write a function that takes `list[Container]` and yields `Finding` objects, then
register it in the `CHECKS` list of the relevant module under `src/ca/checks/`.

---

## 📄 License

[MIT](LICENSE) © 2026 Petr Hromádka
