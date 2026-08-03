# A plain Python 3.12 base: the project requires >=3.12, which the Playwright
# jammy image (Python 3.10) does not satisfy. Chromium's OS libraries and the
# browser itself are installed by Playwright below.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    EF_OUTPUT_DIR=/app/output \
    EF_CACHE_DIR=/tmp/ef-cache \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Dependency layer first so source edits do not invalidate the install.
COPY pyproject.toml README.md ./
COPY endpoint_finder ./endpoint_finder
RUN pip install --no-cache-dir ".[browser,pdf]"

# System libraries (as root) then the browser into a world-readable shared path,
# so the unprivileged scanner user can launch it.
RUN python -m playwright install-deps chromium \
    && python -m playwright install chromium \
    && chmod -R a+rX /ms-playwright \
    && mkdir -p /app/output

# The browser must not run as root.
RUN useradd --create-home --uid 10001 scanner \
    && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["endpoint-finder"]
CMD ["--help"]
