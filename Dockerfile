FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY data/ ./data/

RUN pip install --no-cache-dir ".[scanners]"

RUN mkdir -p /workspace /reports
VOLUME ["/workspace", "/reports"]

ENTRYPOINT ["skills-verified"]
CMD ["--help"]
