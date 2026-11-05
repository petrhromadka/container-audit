# GitHub Action

`container-audit` ships a reusable composite action so any repository can run the auditor in one
step. It installs [uv](https://docs.astral.sh/uv/) and runs the published
[`docker-host-audit`](https://pypi.org/project/docker-host-audit/) package via `uvx`.

## Quick start

```yaml
- uses: petrhromadka/container-audit@v0.2.0
  with:
    fail-on: high
```

By default the action audits the **live Docker host** of the runner. On a standard GitHub-hosted
`ubuntu-latest` runner Docker is available, so this inspects whatever containers are running in the
job.

> **Pin the action.** Reference a release tag (`@v0.2.0`) or a full commit SHA rather than a moving
> branch, so a job cannot silently pull in changes.

## Inputs

All inputs are optional and map to the equivalent CLI flags.

| Input | Default | Meaning |
| --- | --- | --- |
| `input` | `""` | Path to a `docker inspect` JSON array. When empty, the action audits the live Docker host (`docker ps` / `docker inspect`). |
| `format` | `text` | Output format: `text`, `json`, `markdown` or `sarif`. |
| `fail-on` | `none` | Exit non-zero (failing the step) if any finding is at or above this severity: `none`, `low`, `medium`, `high`, `critical`. |
| `min-severity` | `info` | Hide findings below this severity from the report: `info`, `low`, `medium`, `high`, `critical`. |
| `ignore` | `""` | Check ids to suppress, space- or newline-separated (e.g. `docker-socket-mount writable-rootfs`). |
| `version` | `""` | The `docker-host-audit` version/spec to install (e.g. `0.2.0`). Empty installs the latest release. |

## Two modes

**Live audit (default).** Leave `input` empty and the action reads the running containers on the
runner's Docker host:

```yaml
- uses: petrhromadka/container-audit@v0.2.0
  with:
    fail-on: high
```

**Saved dump (`input`).** Point `input` at a `docker inspect` JSON file you captured earlier — useful
for auditing another host's containers, or where the runner has no Docker:

```yaml
- name: Capture containers on the target host
  run: |
    docker inspect $(docker ps -aq) $(docker inspect -f '{{.Image}}' $(docker ps -aq) | sort -u) > containers.json
- uses: petrhromadka/container-audit@v0.2.0
  with:
    input: containers.json
    fail-on: high
```

## SARIF and code scanning

`format: sarif` emits [SARIF](https://sarifweb.azurewebsites.net/) that GitHub reads for code
scanning. The action prints to stdout, so to surface findings in the repository's **Security → Code
scanning** tab, write the output to a file and upload it with a separate step. Capture the output
yourself, or adapt the bundled [`security-scan.yml`](../.github/workflows/security-scan.yml)
workflow, which renders SARIF and uploads it via `github/codeql-action/upload-sarif`.

## Pinning the installed version

Pin both the action and the installed package for reproducible runs:

```yaml
- uses: petrhromadka/container-audit@v0.2.0
  with:
    version: 0.2.0
    format: json
    fail-on: medium
    ignore: |
      writable-rootfs
      unlimited-memory
```
