# Using container-audit as a pre-commit hook

`container-audit` ships a [pre-commit](https://pre-commit.com/) hook so other
repositories can audit a committed `docker-compose.yml` on every commit. This
is **static analysis**: the hook parses the compose file on disk and never
talks to a Docker daemon, so it works in CI and on developer machines without
Docker installed.

## Setup

Add this to the consuming repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/petrhromadka/container-audit
    rev: v0.4.0
    hooks:
      - id: container-audit
```

Then install the hook:

```bash
pre-commit install
```

## What it does

- Runs on any staged file matching
  `(^|/)docker-compose(\.[\w-]+)?\.ya?ml$` — that is `docker-compose.yml`,
  `docker-compose.yaml`, and named variants such as `docker-compose.prod.yml`.
- Invokes `container-audit --compose <file>` for the matched compose file and
  prints the findings.
- Fails the commit when a finding reaches **high** severity or above
  (the hook's default `args: ['--fail-on', 'high']`).

pre-commit installs the package from this repository in its own isolated
environment. The hook declares `additional_dependencies: ['pyyaml>=6']` so
that compose (YAML) parsing works; you do not need to install PyYAML
yourself.

## One compose file at a time

`--compose` accepts exactly one compose PATH. pre-commit appends every matched
filename after the entry, so if several compose files match in a single commit
they would all be passed at once, which `--compose` cannot accept. Most
repositories have a single compose file, so this is rarely an issue. If yours
has more than one, pin the hook to a specific file:

```yaml
repos:
  - repo: https://github.com/petrhromadka/container-audit
    rev: v0.4.0
    hooks:
      - id: container-audit
        files: '^docker-compose\.yml$'
```

## Overriding the arguments

`args` from the hook definition is replaced wholesale when you set your own
`args:` in `.pre-commit-config.yaml`. Keep `--fail-on` if you still want the
commit to fail, then add any extra flags:

```yaml
repos:
  - repo: https://github.com/petrhromadka/container-audit
    rev: v0.4.0
    hooks:
      - id: container-audit
        # fail only on critical findings and suppress one check
        args: ['--fail-on', 'critical', '--ignore', 'writable-rootfs']
```

Without `--fail-on` the tool reports findings but always exits 0, so the commit
would succeed regardless. Useful overrides:

- `--fail-on {low,medium,high,critical}` — severity threshold that fails the commit.
- `--ignore <check-id>` — suppress a specific check (repeatable).
- `--min-severity <level>` — hide findings below a level from the report.
- `--format {text,json,markdown,sarif}` — change the output format.
