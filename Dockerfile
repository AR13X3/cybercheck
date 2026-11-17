# CyberCheck app image: ingest, web, worker and bot (not the page fetcher, see fetcher/Dockerfile).
FROM python:3.13.18-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY cybercheck ./cybercheck
COPY migrations ./migrations
COPY config ./config

RUN useradd --uid 10001 --create-home cybercheck && mkdir -p /app/data && chown cybercheck /app/data
USER cybercheck
ENV CYBERCHECK_DATA_DIR=/app/data
ENTRYPOINT ["python", "-m", "cybercheck"]
