FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./

# Install only runtime deps, system-wide
RUN uv sync --frozen --no-dev --system

COPY src ./src

CMD ["python", "src/worker.py"]
