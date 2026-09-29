FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Pinned, and checked, so a scan can be reproduced from the image.
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
RUN curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

# Semgrep's dependencies clash with FastAPI's, so it lives in its own venv.
ARG SEMGREP_VERSION=1.178.0
ARG SEMGREP_SECURITY_AUDIT_SHA256=b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f
ARG SEMGREP_OWASP_TOP_TEN_SHA256=69d82aea19b412bd6155ea528ffbd272177e4a7f6689014d2a4e6e662d347b56
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && mkdir -p /opt/semgrep-rules \
    && curl -fsSL -o /opt/semgrep-rules/security-audit.yml https://semgrep.dev/c/p/security-audit \
    && curl -fsSL -o /opt/semgrep-rules/owasp-top-ten.yml https://semgrep.dev/c/p/owasp-top-ten \
    && echo "${SEMGREP_SECURITY_AUDIT_SHA256}  /opt/semgrep-rules/security-audit.yml" > /opt/semgrep-rules/SHA256SUMS \
    && echo "${SEMGREP_OWASP_TOP_TEN_SHA256}  /opt/semgrep-rules/owasp-top-ten.yml" >> /opt/semgrep-rules/SHA256SUMS \
    && sha256sum -c /opt/semgrep-rules/SHA256SUMS \
    && chmod -R a+rX /opt/semgrep /opt/semgrep-rules

COPY pyproject.toml ./
COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic

# Dev extras are installed so `pytest` and `ruff` work inside the container.
RUN pip install --no-cache-dir ".[dev]" \
    && rm -rf build *.egg-info \
    && useradd --create-home --uid 1000 panoptes \
    && chown -R panoptes:panoptes /app

USER panoptes

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
