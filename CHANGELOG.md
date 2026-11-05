# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Dockerfile` and `.dockerignore` to run the tool from a container image.
- CI test matrix across Python 3.12, 3.13 and 3.14.
- `publish.yml` workflow to publish to PyPI on release via Trusted Publishing (OIDC).
- `py.typed` marker so type checkers treat the package as typed (PEP 561).
- `CONTRIBUTING.md` and this changelog.

## [0.1.0] - 2026-11-05

Initial release.

### Added

- Read-only audit of Docker hosts using `docker ps` and `docker inspect`, or a saved
  `docker inspect` JSON file via `--input`.
- 15 checks in three groups:
  - Privilege and escape: `docker-socket-mount`, `privileged`, `root-user`, `dangerous-caps`,
    `sensitive-host-mount`.
  - Namespaces and exposure: `host-pid`, `host-network`, `port-all-interfaces`, `host-ipc`,
    `host-uts`.
  - Secrets and hardening: `secret-in-env`, `no-new-privileges-missing`, `writable-rootfs`,
    `unpinned-image`, `unlimited-memory`.
- Text, JSON and Markdown report formats, selected with `--format`.
- `--fail-on LEVEL` to exit non-zero when a finding reaches a severity threshold (exit code `1`;
  `2` when the audit could not run).
- `--include-host` to show the real hostname; it is redacted by default.
- `--include-stopped` to also inspect containers that are not running.
- Secret masking: values of secret-looking environment variables are never printed.
- Sanitization of control and terminal-escape characters from container metadata in reports.
- Read-only guarantee: no container is started, stopped or modified, and no data is sent anywhere.
- No runtime dependencies; requires Python 3.12 or newer.

[Unreleased]: https://github.com/petrhromadka/container-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petrhromadka/container-audit/releases/tag/v0.1.0
