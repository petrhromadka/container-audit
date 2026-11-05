# container-audit

- [x] Skeleton: pyproject, models, checks registry, redact, stubs
- [ ] A: collect.py (parse docker inspect) + docker_cli.py + fixtures
- [ ] B: checks/privilege.py (root, privileged, caps, docker-socket, sensitive mounts)
- [ ] C: checks/exposure.py (ports on 0.0.0.0, secrets in env, image pinning)
- [ ] D: report.py (text/json/markdown) + cli.py
- [ ] E: README, CI, prek, gitleaks, LICENSE, SECURITY.md
- [ ] Merge, full checks, run against sample fixtures
- [ ] Create public repo, push
