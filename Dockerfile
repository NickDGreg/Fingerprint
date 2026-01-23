FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential libfuzzy-dev \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir beautifulsoup4 convex mmh3 requests ssdeep

CMD ["python", "src/worker.py"]
