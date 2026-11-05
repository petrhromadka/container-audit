# Auditing a compose file

`--compose PATH` audits a `docker-compose.yml` **statically**, straight from the file, without a
running Docker daemon and without pulling or starting anything. container-audit reads each service's
security-relevant configuration, maps it onto the same internal model it builds from `docker inspect`,
and runs the exact same checks (see [checks.md](checks.md)). This is handy for reviewing a stack in
CI or a pull request before it is ever deployed.

```bash
container-audit --compose docker-compose.yml --fail-on high
```

## Install the optional extra

Compose parsing uses a YAML dependency that is not installed by default. Install the `[compose]`
extra first:

```bash
pip install docker-host-audit[compose]
# or run it without installing:
uvx --from docker-host-audit[compose] container-audit --compose docker-compose.yml
```

Without the extra, `--compose` exits with an error telling you to install it.

## Mutually exclusive with `--input`

`--compose` and `--input` are mutually exclusive: one audits a compose file, the other a saved
`docker inspect` dump. Passing both is an error. With neither, container-audit audits the live host
via `docker ps` / `docker inspect` as usual.

## What maps to what

Each service under `services:` becomes one audited unit. The following compose fields are read and
fed to the checks:

| Compose field | Used by |
| --- | --- |
| `privileged` | `privileged` |
| `cap_add` | `dangerous-caps` |
| `cap_drop` | `caps-not-dropped` |
| `read_only` | `writable-rootfs` |
| `security_opt` | `no-new-privileges-missing`, `seccomp-unconfined`, `apparmor-unconfined` |
| `user` | `root-user` |
| `pid` | `host-pid` |
| `network_mode` | `host-network`, `shared-network-container` |
| `ipc` | `host-ipc` |
| `uts` | `host-uts` |
| `ports` | `port-all-interfaces` |
| `environment` | `secret-in-env` |
| `mem_limit` | `unlimited-memory` |
| `oom_kill_disable` | `oom-kill-disable` |
| `sysctls` | `dangerous-sysctls` |
| `healthcheck` | `no-healthcheck` |
| `devices` | `host-devices` |
| `volumes` | `docker-socket-mount`, `sensitive-host-mount` |
| `image` | `stale-image`, `unpinned-image` |

### Static-analysis limitations

Because nothing runs, the audit sees only what the file declares:

- `stale-image` needs an image build date, which only a daemon can provide, so it is effectively
  skipped; `unpinned-image` still works from the `image:` string alone.
- Values injected at deploy time (env files, `${VAR}` interpolation from the shell, secrets) are not
  resolved — only literal values in the file are inspected.
- Both the **short** and **long** forms of `ports:` and `volumes:` are supported on a best-effort
  basis. Short forms such as `127.0.0.1:5432:5432` or `/host/path:/container/path:ro` are parsed, as
  are the long mapping forms (`- target: ... published: ...`, `- type: bind source: ... target: ...`).

## Worked example

Given this `docker-compose.yml`:

```yaml
services:
  db:
    image: postgres:latest
    privileged: true
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: hunter2
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  web:
    image: nginx@sha256:abcdef...
    read_only: true
    user: "1000"
    security_opt:
      - "no-new-privileges:true"
    mem_limit: 256m
    ports:
      - "127.0.0.1:8080:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
```

Run:

```bash
container-audit --compose docker-compose.yml --fail-on high
```

The `db` service reports the mounted Docker socket (`docker-socket-mount`), privileged mode
(`privileged`), a published port on all interfaces (`port-all-interfaces`), the password in
`environment` (`secret-in-env`), and the usual hardening gaps. Because at least one finding is
`high` or above, the exit code is `1`, failing the CI job. The hardened `web` service (read-only
root, non-root user, `no-new-privileges`, memory limit, port bound to `127.0.0.1`, healthcheck,
pinned by digest) produces no findings.
