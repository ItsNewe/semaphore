ARG SYFT_VERSION=latest
ARG GRYPE_VERSION=latest
ARG CRANE_VERSION=latest
ARG PYTHON_VERSION=3.14
ARG UV_VERSION=0.13.6

FROM anchore/syft:${SYFT_VERSION} AS syft
FROM anchore/grype:${GRYPE_VERSION} AS grype
FROM gcr.io/go-containerregistry/crane:${CRANE_VERSION} AS crane
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:${PYTHON_VERSION}-slim
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=crane /ko-app/crane /usr/local/bin/crane
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app
# Dependencies first so they stay cached when only the source changes
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false

VOLUME /data
ENTRYPOINT ["/app/.venv/bin/semaphore"]
