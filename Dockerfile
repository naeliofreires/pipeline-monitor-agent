FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY config.yaml ./config.yaml

RUN pip install --no-cache-dir .

# Run as a non-root user; the SQLite state lives in /app/data (a mounted volume),
# which must be writable by that user.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data
USER appuser

CMD ["pipeline-monitor", "--config", "/app/config.yaml"]
