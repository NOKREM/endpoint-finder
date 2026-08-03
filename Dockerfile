# Playwright's own image ships Chromium plus every system library it needs.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    EF_OUTPUT_DIR=/app/output \
    EF_CACHE_DIR=/tmp/ef-cache

WORKDIR /app

# Dependency layer first so source edits do not invalidate the install.
COPY pyproject.toml README.md ./
COPY endpoint_finder ./endpoint_finder
RUN pip install --no-cache-dir ".[browser,pdf]" \
    && python -m playwright install chromium \
    && mkdir -p /app/output

# The browser must not run as root.
RUN useradd --create-home --uid 10001 scanner \
    && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["endpoint-finder"]
CMD ["--help"]
