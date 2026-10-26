# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Build arg lets CI stamp the exact revision for version-safe deployments.
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION} \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SECSCAN_DATA_DIR=/data

WORKDIR /app

# Optional: bundle trivy for full SBOM + CVE scanning of Docker images.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Install the package (and its dependencies) — source must be present first so
# setuptools can discover the app.* subpackages.
COPY pyproject.toml ./
COPY app ./app
RUN pip install --upgrade pip && pip install .

# Create the unprivileged user that the app runs as.
RUN useradd --system --create-home argus \
    && mkdir -p /data && chown -R argus:argus /data /app

# Entrypoint starts as root, fixes /data ownership for any mount, then drops to
# 'argus' and execs the app — so operators can mount any folder at /data.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

# Honors SECSCAN_HOST/PORT/RELOAD via the module entrypoint.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "-m", "app"]
