"""Integration tests against a disposable Postgres (scripts/it-postgres.sh). Skipped unless CYBERCHECK_IT_PG
is set to that server's admin URL. Each test module gets its own fresh database with every migration applied,
dropped afterwards. A shared or production Postgres is never used here."""
from __future__ import annotations

import asyncio
import os
import re
import uuid

import psycopg
import pytest

ADMIN = os.environ.get("CYBERCHECK_IT_PG", "")
if ADMIN and not re.match(r"^postgresql://[^@]+@127\.0\.0\.1:55432/", ADMIN):
    raise RuntimeError("CYBERCHECK_IT_PG must point at the disposable server on 127.0.0.1:55432")


def pytest_collection_modifyitems(config, items):
    if ADMIN:
        return
    skip = pytest.mark.skip(reason="set CYBERCHECK_IT_PG (scripts/it-postgres.sh start) to run integration tests")
    for item in items:
        if "tests/integration" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="module")
def it_db(tmp_path_factory, request):
    """A fresh migrated database for this test module. Sets DATABASE_URL and CYBERCHECK_DATA_DIR (a temp dir)
    and resets cybercheck.config.settings() and the db pool around the module. Yields the database URL."""
    from cybercheck import config, db
    name = "it_" + re.sub(r"\W", "_", request.module.__name__.rsplit(".", 1)[-1])[:40] + "_" + uuid.uuid4().hex[:6]
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    url = ADMIN.rsplit("/", 1)[0] + "/" + name
    data_dir = tmp_path_factory.mktemp("data")
    old = {k: os.environ.get(k) for k in ("DATABASE_URL", "CYBERCHECK_DATA_DIR")}
    os.environ["DATABASE_URL"] = url
    os.environ["CYBERCHECK_DATA_DIR"] = str(data_dir)
    config.settings.cache_clear()
    db._pool = None
    db.migrate()
    try:
        yield url
    finally:
        if db._pool is not None:
            try:
                asyncio.run(db.close())
            except Exception:
                db._pool = None
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        config.settings.cache_clear()
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
