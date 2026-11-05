# Security Policy

container-audit is a defensive auditing tool. It is read-only: it runs `docker ps` and
`docker inspect` (or parses a saved copy of that JSON), never changes a container, and never
transmits data anywhere.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/petrhromadka/container-audit/security/advisories/new)
rather than a public issue.

Useful things to include:

- the version or commit you tested,
- steps or an input file that reproduces the problem,
- the impact you expect (for example, a secret value appearing in output, or the tool performing
  a write operation).

Reports that a secret **value** is printed anywhere in text, JSON, or Markdown output, or that the
tool can modify a container, are treated as the highest priority.

## Supported versions

Only the latest release receives security fixes.
