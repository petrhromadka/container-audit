# Minimal image that runs container-audit. The Docker CLI is intentionally NOT
# bundled; feed it a saved inspect dump via --input (see README), e.g.:
#   docker inspect $(docker ps -aq) | docker run --rm -i IMAGE --input /dev/stdin
FROM python:3.13-slim

# Install uv to build and install the package.
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv

WORKDIR /app
COPY . /app
RUN uv pip install --system --no-cache . \
    && adduser --disabled-password --gecos "" auditor
USER auditor

ENTRYPOINT ["container-audit"]
CMD ["--help"]
