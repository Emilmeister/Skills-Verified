FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        npm \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        bandit \
        pip-audit \
        semgrep

FROM base AS app

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["skills-verified"]
