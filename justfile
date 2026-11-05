# Dev task runner for container-audit.
# Recipes use `python -m ca` so they work where the generated console
# script (e.g. container-audit.exe under Windows Smart App Control) is blocked.

# List available recipes.
default:
    @just --list

# Create / sync the environment.
sync:
    uv sync

# Lint.
lint:
    uv run ruff check .

# Format in place.
fmt:
    uv run ruff format .

# Check formatting without changing files.
fmt-check:
    uv run ruff format --check .

# Type check.
types:
    uv run ty check src

# Run the test suite.
test:
    uv run python -m pytest

# Run all checks (lint, formatting, types, tests).
check: lint fmt-check types test

# Run the auditor, e.g. `just audit --input tests/fixtures/sample_inspect.json`.
audit *ARGS:
    uv run python -m ca {{ARGS}}

# Build the distribution.
build:
    uv build
