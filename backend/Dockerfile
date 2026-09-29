FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic

# Dev extras are installed so `pytest` and `ruff` work inside the container
# during local verification. Scanner binaries are added in later phases.
RUN pip install --no-cache-dir ".[dev]" \
    && useradd --create-home --uid 1000 panoptes \
    && chown -R panoptes:panoptes /app

USER panoptes

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
