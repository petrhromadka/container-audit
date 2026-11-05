# container-audit

**Read-only security audit for Docker hosts.** It inspects your containers and reports risky
configuration: root users, exposed ports, secrets in environment variables, privileged mode,
dangerous capabilities, mounted Docker sockets, sensitive host mounts, shared host namespaces,
missing hardening options and unpinned images.

[![CI](https://github.com/petrhromadka/container-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/petrhromadka/container-audit/actions/workflows/ci.yml)
![defensive](https://img.shields.io/badge/purpose-defensive-blue)
![read-only](https://img.shields.io/badge/access-read--only-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-informational)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

> **Defensive and read-only.** container-audit only runs `docker ps` and `docker inspect` (or
> reads a saved copy of that JSON). It never starts, stops, or modifies a container, and it never
> sends data anywhere.

---

## Quick start

No Docker needed to try it — the repo ships a sample `docker inspect` dump:

```bash
git clone https://github.com/petrhromadka/container-audit
cd container-audit
uv run container-audit --input tests/fixtures/sample_inspect.json
```

You'll see ten findings on the intentionally-insecure `bad-db` container and a clean bill of
health for the hardened `good-web` one. To scan your own host instead, just run `container-audit`
(it reads live containers via `docker ps` / `docker inspect`).

---

## What it checks

| Check id                    | Severity | What                                                                | Why it matters                                                                                     |
| --------------------------- | -------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `docker-socket-mount`       | critical | `/var/run/docker.sock` is mounted into the container                | Access to the socket is effectively root on the host: the container can start any other container. |
| `privileged`                | critical | Container runs with `--privileged`                                  | Disables most isolation: full device access and all capabilities.                                  |
| `root-user`                 | high     | Container runs as root (no `USER`, or `0` / `root`)                 | A process escape or file-permission bug has root privileges inside the container.                   |
| `dangerous-caps`            | high     | Capabilities such as `SYS_ADMIN`, `NET_ADMIN` or `SYS_PTRACE` added | These widen the attack surface and are common container-escape building blocks.                     |
| `secret-in-env`             | high     | Env var names that look like secrets (password, token, key, …)      | Secrets in env vars leak through `docker inspect`, logs and child processes.                        |
| `sensitive-host-mount`      | high     | Host paths such as `/`, `/etc`, `/proc` or `/root` are bind-mounted | A compromised container can read or alter host configuration and credentials.                       |
| `host-pid`                  | high     | Container shares the host PID namespace (`--pid=host`)              | It can see and signal every process on the host.                                                   |
| `host-network`              | high     | Container shares the host network namespace (`--network=host`)      | Network isolation and port mapping are bypassed; it binds directly on host interfaces.             |
| `port-all-interfaces`       | medium   | Port published on all interfaces (`0.0.0.0` or `::`)                | The service is reachable from every network the host is on, not just where you intend.             |
| `host-ipc`                  | medium   | Container shares the host IPC namespace (`--ipc=host`)             | Shared memory and semaphores cross the container boundary.                                          |
| `no-new-privileges-missing` | medium   | `no-new-privileges` is not set in `SecurityOpt`                     | setuid binaries inside the container can still escalate privileges.                                 |
| `writable-rootfs`           | low      | Root filesystem is writable (not `read_only`)                      | An attacker can persist changes and tooling inside the container.                                   |
| `unpinned-image`            | low      | Image uses `:latest`, no tag, or no digest                         | Pulls are not reproducible and a changed upstream image can silently alter what runs.              |
| `host-uts`                  | low      | Container shares the host UTS namespace (`--uts=host`)             | It can change the host's hostname.                                                                  |
| `unlimited-memory`          | low      | No memory limit set                                                | A single container can exhaust host RAM and take the host down.                                     |

Findings are ordered from `critical` down. Each finding carries a title, a human-readable
explanation, short redacted evidence, and a one-line remediation.

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). The `docker` CLI is only needed when
you audit a live host; auditing a saved file with `--input` does not need it.

```bash
# Install as a tool from a checkout
uv tool install .

# Or run it without installing
uvx --from . container-audit

# Or run it from a checkout inside the project environment
uv run container-audit
```

## Usage

```bash
# Audit running containers on this host
container-audit

# Include stopped containers too
container-audit --include-stopped

# Audit a saved `docker inspect` file instead of talking to Docker
docker inspect $(docker ps -aq) > sample.json
container-audit --input sample.json

# Produce a Markdown report (for an issue, wiki page or PR comment)
container-audit --input sample.json --format markdown > report.md

# Machine-readable output
container-audit --format json

# Fail a CI job when anything high or worse is found
container-audit --fail-on high
```

| Flag                | Meaning                                                                            |
| ------------------- | ---------------------------------------------------------------------------------- |
| `--input FILE`      | Read `docker inspect` JSON from `FILE` instead of calling Docker.                   |
| `--format FORMAT`   | Output format: `text` (default), `json` or `markdown`.                             |
| `--include-stopped` | Also inspect containers that are not running.                                      |
| `--include-host`    | Include the real hostname in the report (off by default, so output is safe to share). |
| `--fail-on LEVEL`   | Exit non-zero if any finding is at or above `LEVEL` (`none`, `low`, `medium`, `high`, `critical`). Default `none`. |

### Exit codes

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Ran successfully; no finding reached the `--fail-on` threshold.             |
| `1`  | Ran successfully, but a finding was at or above `--fail-on`.                |
| `2`  | Could not run: Docker unavailable, or the `--input` file was missing/invalid. |

### Use in CI

Gate a pipeline on the audit by scanning a saved inspect dump and failing on high-severity issues:

```yaml
- name: Audit containers
  run: |
    docker inspect $(docker ps -aq) > containers.json
    uvx --from git+https://github.com/petrhromadka/container-audit \
      container-audit --input containers.json --fail-on high
```

## How it works

```text
docker ps / docker inspect  ->  parse into Container objects  ->  run checks  ->  render report
        (or --input file)                                          (pure functions)   text / json / markdown
```

1. **Collect.** The tool lists containers with `docker ps` and reads their configuration with
   `docker inspect`. With `--input`, it parses a saved copy of that JSON instead.
2. **Check.** Each check is a pure function that takes the parsed containers and yields findings.
   Checks never talk to Docker and never change anything.
3. **Report.** Findings are sorted by severity and rendered as text, JSON or Markdown. With
   `--fail-on`, the exit code reflects the worst severity found.

## Safety

- **Read-only.** The only Docker commands used are `docker ps` and `docker inspect`. Nothing is
  started, stopped, restarted, or reconfigured.
- **Secret values are never printed.** For environment variables that look like secrets, only the
  variable **name** is reported, with the value masked to `***` — no characters of the value appear
  in text, JSON, or Markdown output.
- **Hostname hidden by default.** The report shows `(redacted)` as the host unless you pass
  `--include-host`.
- **Output is sanitized.** Control and terminal-escape characters from container metadata are
  stripped so a report is safe to print in a terminal or paste into Markdown.
- **No network use.** The tool does not transmit data anywhere and has no runtime dependencies.
- Reports can still reveal your container names, image names, ports and mount paths. Review a
  report before sharing it publicly.

## Example output

Generated from `tests/fixtures/sample_inspect.json`, which contains only made-up data.

```text
container-audit report
Host:      (redacted)
Scanned:   2 container(s)
Timestamp: 2026-11-05T19:32:19+00:00
Findings:  10 (critical=2, high=3, medium=3, low=2, info=0)

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
[LOW] unlimited-memory  bad-db - With no memory limit, one container can exhaust the host's RAM.
    evidence:    HostConfig.Memory=0
    remediation: Set a memory limit (`mem_limit` in compose).
[LOW] writable-rootfs  bad-db - A writable root filesystem lets an attacker persist changes.
    evidence:    HostConfig.ReadonlyRootfs=false
    remediation: Set `read_only: true` and use tmpfs or volumes for writable paths.
```

The second container in the fixture, `good-web`, is hardened (non-root, read-only rootfs, memory
limit, `no-new-privileges`, port bound to `127.0.0.1`) and produces no findings.

## Development

```bash
uv sync                      # create the environment
uv run ruff check .          # lint
uv run ruff format --check . # formatting
uv run ty check src          # type check
uv run pytest                # tests
```

Pre-commit hooks (ruff, gitleaks, whitespace fixes) are defined in `.pre-commit-config.yaml`;
install them with [`prek`](https://github.com/j178/prek) or `pre-commit`. CI runs the same checks
plus a gitleaks scan.

To add a check, write a function that takes `list[Container]` and yields `Finding` objects, then
register it in the `CHECKS` list of the relevant module under `src/ca/checks/`.

## License

[MIT](LICENSE) © 2026 Petr Hromádka
