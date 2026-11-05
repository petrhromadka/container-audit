---
name: Bug report
about: Report incorrect behavior, a crash, or a wrong finding
title: "[Bug]: "
labels: ["bug"]
---

<!--
Thanks for reporting a bug. container-audit is read-only and security-focused,
so please be careful not to leak real secrets or private host details below.
-->

## What happened

A clear description of the problem.

## Steps to reproduce

1. The exact command you ran, e.g.:

   ```bash
   container-audit --input inspect.json --fail-on high
   ```

2. If you can, attach a **redacted** `--input` JSON that reproduces the issue.

> [!WARNING]
> Do **not** paste real secrets, passwords, tokens, tokens-in-URLs, real
> hostnames or IP addresses. Replace them with placeholders before sharing.

## Expected vs actual

- **Expected:** what you thought would happen.
- **Actual:** what happened instead (paste the relevant, redacted output).

## Version

Output of:

```bash
container-audit --version
```

## Environment

- OS (and version):
- Python version (`python --version`):
- Docker version (`docker --version`), if auditing a live host:
