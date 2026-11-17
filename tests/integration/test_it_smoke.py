"""Smoke test for the integration harness: migrations apply on a fresh database and are idempotent."""
from cybercheck import db


def test_migrations_apply_and_rerun(it_db):
    assert db.migrate() == []          # second run: nothing left to apply
    with db.connect_sync() as c:
        names = {r["version"] for r in c.execute("SELECT version FROM schema_migrations")}
        assert {"001_init.sql", "020_fetch.sql", "040_reporting.sql", "060_czds.sql", "080_review_scope.sql"} <= names
        cols = {r["column_name"] for r in c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'domains'")}
        assert {"reviewed_hostnames", "fetch_state", "next_fetch_at", "final_score"} <= cols
