"""Postgres access (psycopg 3). One async pool per process; sync connections for the CLI."""
from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from .config import ROOT, settings

_pool: AsyncConnectionPool | None = None
# Every session in UTC: templates and logs label times "UTC", and the CZDS 24 h rule does wall-clock arithmetic
# on returned timestamps. Without this, an ALTER DATABASE/ROLE ... SET timezone would silently shift them.
# CYBERCHECK_DB_OPTIONS="" turns it off (tests use that to prove the code is right under other zones too).


def _conn_kwargs() -> dict:
    opts = os.environ.get("CYBERCHECK_DB_OPTIONS", "-c TimeZone=UTC")
    return {"options": opts} if opts else {}


async def pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        # check: test a pooled connection before handing it out, so connections killed by a Postgres restart
        # (or a paused login / pg_terminate_backend) are replaced instead of failing the next caller.
        _pool = AsyncConnectionPool(settings().database_url, min_size=1, max_size=5,
                                    kwargs={"row_factory": dict_row, "autocommit": True, **_conn_kwargs()},
                                    open=False,
                                    check=AsyncConnectionPool.check_connection)
        await _pool.open()
    return _pool


async def close() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def connect_sync() -> psycopg.Connection:
    return psycopg.connect(settings().database_url, row_factory=dict_row, autocommit=True, **_conn_kwargs())


def jsonb(value) -> Jsonb:
    return Jsonb(value)


def migrate() -> list[str]:
    """Apply migrations/*.sql in name order, once each."""
    applied = []
    with connect_sync() as conn:
        conn.execute("SELECT pg_advisory_lock(727001)")  # one migrator at a time across containers
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
        done = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
        for path in sorted((ROOT / "migrations").glob("*.sql")):
            if path.name in done:
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
            applied.append(path.name)
        conn.execute("SELECT pg_advisory_unlock(727001)")
    return applied


async def add_event(conn, domain_id: int, kind: str, detail: dict | None = None) -> None:
    await conn.execute("INSERT INTO domain_events (domain_id, kind, detail) VALUES (%s, %s, %s)",
                       (domain_id, kind, Jsonb(detail or {})))


async def kv_get(conn, key: str, default=None):
    row = await (await conn.execute("SELECT value FROM kv WHERE key = %s", (key,))).fetchone()
    return row["value"] if row else default


async def kv_set(conn, key: str, value) -> None:
    await conn.execute(
        "INSERT INTO kv (key, value, updated_at) VALUES (%s, %s, now()) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        (key, Jsonb(value)))


def dumps(value) -> str:
    return json.dumps(value, default=str)


__all__ = ["pool", "close", "connect_sync", "jsonb", "migrate", "add_event", "kv_get", "kv_set", "dumps", "Path"]
