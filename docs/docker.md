# Running the published Docker image

Each published GitHub release builds the image from the repository
[`Dockerfile`](../Dockerfile) and pushes it to the GitHub Container Registry at
`ghcr.io/petrhromadka/container-audit`.

The Docker CLI is **intentionally not bundled** in the image (keeping it minimal
and read-only), so you cannot call `docker ps` / `docker inspect` from inside the
container. Instead you run `docker inspect` on the host and pipe its JSON dump
into the container on stdin, pointing `--input` at `/dev/stdin`.

## Tags

- `ghcr.io/petrhromadka/container-audit:latest` — the most recent release.
- `ghcr.io/petrhromadka/container-audit:X.Y.Z` — a specific release version.
- `ghcr.io/petrhromadka/container-audit:X.Y` — the latest patch of a minor line.

Pin to a version tag for reproducible CI; use `latest` for interactive runs.

## Audit a saved dump

Save a `docker inspect` dump to a file, then feed it in on stdin:

```bash
docker run --rm -i ghcr.io/petrhromadka/container-audit:latest --input /dev/stdin < inspect.json
```

## Audit the live host in one pipe

Run `docker inspect` on the host and pipe the result straight into the container.
Exit non-zero if any finding is `high` or above:

```bash
docker inspect $(docker ps -aq) | docker run --rm -i ghcr.io/petrhromadka/container-audit --input /dev/stdin --fail-on high
```

The flags (`--input`, `--format`, `--fail-on`, `--ignore`, …) are the same as the
CLI; see the [README](../README.md#-usage) for the full list.
