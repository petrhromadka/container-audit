# container-audit

**Read-only security audit for Docker hosts.** It inspects your containers and reports risky
configuration: root users, exposed ports, secrets in environment variables, privileged mode,
dangerous capabilities, mounted Docker sockets, sensitive host mounts and unpinned images.

![defensive](https://img.shields.io/badge/purpose-defensive-blue)
![read-only](https://img.shields.io/badge/access-read--only-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-informational)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

> **Defensive and read-only.** container-audit only runs `docker ps` and `docker inspect` (or
> reads a saved copy of that JSON). It never starts, stops, or modifies a container, and it never
> sends data anywhere.

---

## What it checks

| Check id               | Severity | What                                                          | Why it matters                                                                                  |
| ---------------------- | -------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `docker-socket-mount`  | critical | `/var/run/docker.sock` is mounted into the container          | Access to the socket is effectively root on the host: the container can start any other container. |
| `privileged-container` | critical | Container runs with `--privileged`                            | Disables most isolation: full device access and all capabilities.                               |
| `dangerous-capability` | high     | Capabilities such as `SYS_ADMIN`, `NET_ADMIN` or `SYS_PTRACE` are added | These widen the attack surface and are common container-escape building blocks.        |
| `sensitive-host-mount` | high     | Host paths such as `/`, `/etc`, `/proc` or `/root` are bind-mounted | A compromised container can read or alter host configuration and credentials.             |
| `secret-in-env`        | high     | Environment variable names that look like secrets (password, token, key) | Secrets in env vars leak through `docker inspect`, logs and child processes.       |
| `exposed-port`         | medium   | Port published on all interfaces (`0.0.0.0` or `::`)          | The service is reachable from every network the host is on, not just where you intend.          |
| `root-user`            | medium   | Container runs as root (no `USER`, or `0` / `root`)           | A process escape or file-permission bug has root privileges inside the container.               |
| `unpinned-image`       | low      | Image uses `:latest`, no tag, or no digest                    | Pulls are not reproducible and a changed upstream image can silently alter what runs.           |

Findings are ordered from `critical` down to `info`. Each finding carries a title, a
human-readable explanation, short redacted evidence, and a one-line remediation.

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

| Flag                | Meaning                                                                     |
| ------------------- | --------------------------------------------------------------------------- |
| `--input FILE`      | Read `docker inspect` JSON from `FILE` instead of calling Docker.           |
| `--format FORMAT`   | Output format: `text` (default), `json` or `markdown`.                      |
| `--include-stopped` | Also inspect containers that are not running.                               |
| `--fail-on LEVEL`   | Exit non-zero if any finding is at or above `LEVEL` (`info` to `critical`). |

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
  variable **name** is reported, together with a masked hint (for example `su***`). The full value
  does not appear in text, JSON, or Markdown output.
- **No network use.** The tool does not transmit data anywhere and has no runtime dependencies.
- Reports can still reveal your container names, image names, ports and mount paths. Review a
  report before sharing it publicly.

## Example output

The hosts, names and values below are made up.

```text
container-audit report
host: docker-host-01    scanned: 4 containers    2026-01-15T09:30:00Z

[CRITICAL] docker-socket-mount  (ci-runner)
  /var/run/docker.sock is mounted into the container.
  evidence:    /var/run/docker.sock -> /var/run/docker.sock (rw)
  remediation: Remove the mount, or use a socket proxy with a restricted API.

[HIGH] secret-in-env  (web-app)
  Environment variable looks like a secret.
  evidence:    DB_PASSWORD=ex***
  remediation: Use Docker secrets or a secret manager instead of env vars.

[MEDIUM] exposed-port  (postgres)
  Port is published on all interfaces.
  evidence:    0.0.0.0:5432->5432/tcp
  remediation: Bind to 127.0.0.1 or a private interface, e.g. 127.0.0.1:5432:5432.

[MEDIUM] root-user  (web-app)
  Container runs as root.
  evidence:    Config.User = ""
  remediation: Set a non-root USER in the image or run with --user.

[LOW] unpinned-image  (postgres)
  Image tag is not pinned.
  evidence:    postgres:latest
  remediation: Pin to a specific version or digest.

summary: 1 critical, 1 high, 2 medium, 1 low, 0 info
```

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
