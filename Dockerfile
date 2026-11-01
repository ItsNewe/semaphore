ARG SYFT_VERSION=latest
ARG GRYPE_VERSION=latest
ARG PYTHON_VERSION=3.14

FROM anchore/syft:${SYFT_VERSION} AS syft
FROM anchore/grype:${GRYPE_VERSION} AS grype

FROM python:${PYTHON_VERSION}-slim
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
RUN pip install --no-cache-dir "docker>=7.1" "apprise>=1.9"

WORKDIR /app
COPY scanner.py .

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false

VOLUME /data
ENTRYPOINT ["python", "/app/scanner.py"]
