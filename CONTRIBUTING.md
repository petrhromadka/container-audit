# Contributing

Thanks for helping improve container-audit. The tool is defensive and read-only: it must never
start, stop or modify a container, and it must never send data anywhere. Please keep it that way.

## Prerequisites

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)
- The `docker` CLI is optional; tests and `--input` runs work without it.

## Setup

```bash
uv sync
```

## Checks

Run all of these before opening a pull request. CI runs the same ones.

```bash
uv run ruff check .          # lint
uv run ruff format --check . # formatting
uv run ty check src          # type check
uv run pytest                # tests
```

## Running the tool locally

```bash
uv run python -m ca.cli --input tests/fixtures/sample_inspect.json
```

On Windows, Smart App Control may block the generated `container-audit.exe` console script. Use
`python -m ca.cli` or `uv run python -m ca.cli` instead.

## Adding a check

1. Write a pure function that takes `list[Container]` and yields `Finding` objects. It must not call
   Docker or touch the filesystem or network.
2. Append it to the `CHECKS` list of the relevant module under `src/ca/checks/`
   (`privilege.py`, `exposure.py` or `hardening.py`).
3. Add a test in the matching `tests/test_<module>.py`: one case that triggers the finding and one
   that does not.
4. Add a row for it to the check tables in `README.md`.
5. Never put secret values in evidence; mask them (see the existing `secret-in-env` check).

## Pre-commit hooks

Hooks (ruff, gitleaks, whitespace fixes) are defined in `.pre-commit-config.yaml`. Install them with
[`prek`](https://github.com/j178/prek) or `pre-commit`, and run `prek run` before committing.

## Commits

Use short, imperative subjects (72 characters or fewer), one logical change per commit.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public issue.
