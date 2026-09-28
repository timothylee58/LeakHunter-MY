FROM python:3.11-slim

LABEL org.opencontainers.image.title="LeakHunter MY" \
      org.opencontainers.image.description="Deterministic Malaysian PII leak detector" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install only runtime deps first for better layer caching
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir -e . --no-deps || true

COPY leakhunter/ ./leakhunter/
RUN pip install --no-cache-dir -e .

# Default: scan /src (mount your project there)
ENTRYPOINT ["leakhunter", "scan"]
CMD ["/src", "--fail-on", "high"]
