#!/usr/bin/env bash
# Disposable Postgres for the integration tests (tests/integration/). Never your real Postgres:
# a throwaway container on 127.0.0.1:55432 with its data in tmpfs, gone when stopped.
#
#   ./scripts/it-postgres.sh start      # prints the export line for CYBERCHECK_IT_PG
#   CYBERCHECK_IT_PG=postgresql://postgres:cybercheck-it@127.0.0.1:55432/postgres .venv/bin/python -m pytest -q tests/integration
#   ./scripts/it-postgres.sh stop
set -eu
NAME=cybercheck-it-pg
IMAGE=pgvector/pgvector:0.8.7-pg17      # Postgres 17 with pgvector, as in production
PORT=55432
URL="postgresql://postgres:cybercheck-it@127.0.0.1:${PORT}/postgres"
case "${1:-}" in
  start)
    if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
      docker run -d --rm --name "$NAME" -p "127.0.0.1:${PORT}:5432" \
        -e POSTGRES_PASSWORD=cybercheck-it --tmpfs /var/lib/postgresql/data:rw,size=512m \
        --memory 384m --log-opt max-size=10m --log-opt max-file=3 "$IMAGE" \
        -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=200 >/dev/null
    fi
    for _ in $(seq 1 60); do
      docker exec "$NAME" pg_isready -U postgres -q 2>/dev/null && break
      sleep 0.5
    done
    docker exec "$NAME" pg_isready -U postgres -q
    echo "export CYBERCHECK_IT_PG=$URL"
    ;;
  stop) docker stop "$NAME" >/dev/null 2>&1 || true; echo stopped ;;
  url) echo "$URL" ;;
  *) echo "usage: $0 start|stop|url" >&2; exit 2 ;;
esac
