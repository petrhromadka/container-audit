# Checks reference

This is the complete list of every check container-audit runs, grouped by category. Each check is a
pure function over the parsed containers; it never talks to Docker and never changes anything.

## Severities

Every finding carries one of four severities:

- 🔴 **critical** — a compromise of the container is effectively a compromise of the host.
- 🟠 **high** — a serious weakness that materially widens the blast radius of an attack.
- 🟡 **medium** — a meaningful hardening gap worth fixing.
- 🔵 **low** — a best-practice deviation with limited direct impact.

Use `--min-severity LEVEL` to hide findings below a level and `--fail-on LEVEL` to make CI fail at or
above one.

## Evidence is redacted

Every finding includes a short piece of **evidence** so you can confirm it, but evidence is always
sanitized: secret values are masked to `***` (only the variable name is shown), the hostname is
`(redacted)` unless you pass `--include-host`, and control and terminal-escape characters are
stripped. A report is therefore safe to print or paste into Markdown, though it can still reveal
container names, image names, ports and mount paths.

## Privilege &amp; escape

| | Check id | What triggers it | Why it matters | Remediation |
| :-: | --- | --- | --- | --- |
| 🔴 | `privileged` | The container runs in privileged mode (`HostConfig.Privileged=true`). | Privileged mode grants all capabilities and host device access, so a compromise is effectively a host compromise. | Remove `privileged: true`; add only the capabilities needed. |
| 🔴 | `docker-socket-mount` | A mount whose source ends in `docker.sock` is present. | Access to the Docker socket grants control of the Docker daemon, and therefore of the host. | Remove the socket mount or use a restricted docker-socket-proxy. |
| 🟠 | `root-user` | The container's main process runs as UID 0 (no `USER`, or `0`/`root`). | The main process runs as UID 0, widening the impact of an escape. | Set a non-root USER in the image or `user:` in compose. |
| 🟠 | `dangerous-caps` | One of `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_READ_SEARCH` is in `cap_add`. | These capabilities allow administrative or host-affecting operations and weaken container isolation. | Remove these from `cap_add`; grant only what is required. |
| 🟠 | `sensitive-host-mount` | A sensitive host path (`/`, `/etc`, `/root`, `/var/run`, `/proc`, `/sys`, `/home`) is bind-mounted read-write. | A writable bind mount of a sensitive host directory lets the container modify host configuration or data. | Mount a narrower path, and read-only (`:ro`) where possible. |

## Namespaces &amp; exposure

| | Check id | What triggers it | Why it matters | Remediation |
| :-: | --- | --- | --- | --- |
| 🟠 | `host-pid` | The container shares the host PID namespace (`HostConfig.PidMode=host`). | The container can see and signal host processes, undermining isolation. | Remove `pid: host` from the container configuration. |
| 🟠 | `host-network` | The container shares the host network namespace (`HostConfig.NetworkMode=host`). | The container shares the host network namespace, bypassing network isolation and port mapping. | Use a bridge or user-defined network instead of `network_mode: host`. |
| 🟡 | `port-all-interfaces` | A port is published on all interfaces (`0.0.0.0` / `::`). | The port is reachable from every network the host is attached to. | Bind to 127.0.0.1 (e.g. `127.0.0.1:<port>:<port>`) unless public. |
| 🟡 | `host-ipc` | The container shares the host IPC namespace (`HostConfig.IpcMode=host`). | The container can access host shared memory and IPC objects, weakening isolation. | Remove `ipc: host`; do not share the host IPC namespace. |
| 🔵 | `host-uts` | The container shares the host UTS namespace (`HostConfig.UTSMode=host`). | The container shares the host hostname and domain name namespace. | Remove `uts: host`; do not share the host UTS namespace. |

## Secrets &amp; hardening

| | Check id | What triggers it | Why it matters | Remediation |
| :-: | --- | --- | --- | --- |
| 🟠 | `secret-in-env` | An env var name looks like a secret, or a value contains URL-embedded credentials, with a literal (non-placeholder) value. | The variable looks like a secret and has a literal value; it is visible via `docker inspect` and to anyone who can read the container configuration. | Use Docker secrets or an env file kept outside the image. |
| 🟡 | `no-new-privileges-missing` | `no-new-privileges:true` is absent from `HostConfig.SecurityOpt`. | Without no-new-privileges, setuid binaries inside the container can escalate privileges. | Add `security_opt: ["no-new-privileges:true"]`. |
| 🔵 | `writable-rootfs` | The root filesystem is writable (`HostConfig.ReadonlyRootfs=false`). | A writable root filesystem lets an attacker persist changes. | Set `read_only: true` and use tmpfs or volumes for writable paths. |
| 🔵 | `unlimited-memory` | No memory limit is set (`HostConfig.Memory=0`). | With no memory limit, one container can exhaust the host's RAM. | Set a memory limit (`mem_limit` in compose). |

## Runtime hardening

| | Check id | What triggers it | Why it matters | Remediation |
| :-: | --- | --- | --- | --- |
| 🟠 | `seccomp-unconfined` | The seccomp profile is disabled (`seccomp=unconfined`). | With seccomp off, the container can make the full set of syscalls, widening the kernel attack surface available for an escape. | Drop `seccomp=unconfined`; keep Docker's default seccomp profile or supply a tailored one. |
| 🟡 | `apparmor-unconfined` | The AppArmor profile is disabled (`apparmor=unconfined`). | Without an AppArmor profile, mandatory access control is off, so a compromised process is unconstrained by the host's security policy. | Remove `apparmor=unconfined`; keep the `docker-default` profile or apply a custom one. |
| 🔵 | `caps-not-dropped` | Linux capabilities are not dropped to `ALL` before adding back only what is needed. | Keeping the default capability set grants more privileges than most workloads use, enlarging the attack surface. | Drop all capabilities (`cap_drop: [ALL]`) and add back only the ones the workload requires. |
| 🔵 | `no-healthcheck` | The container defines no healthcheck. | Without a healthcheck, the orchestrator cannot tell a hung or unhealthy container from a working one, so failures go unnoticed. | Add a `HEALTHCHECK` to the image or a `healthcheck:` to the container configuration. |

## Images

| | Check id | What triggers it | Why it matters | Remediation |
| :-: | --- | --- | --- | --- |
| 🟡 | `stale-image` | The image was built more than 180 days ago. | The image is old, so it likely lacks security patches released since it was built. | Pull or rebuild the image on a current base and recreate the container; automate updates (e.g. Renovate, Dependabot). |
| 🔵 | `unpinned-image` | The image uses `:latest`, no tag, or no digest. | The image has no digest and uses no tag or the mutable `:latest` tag, so pulls are not reproducible. | Pin to a digest (`@sha256:...`) or an explicit version tag. |

---

**20 checks total:** 5 privilege &amp; escape, 5 namespaces &amp; exposure, 4 secrets &amp; hardening,
4 runtime hardening, 2 images.
