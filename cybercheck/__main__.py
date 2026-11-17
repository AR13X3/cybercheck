"""CyberCheck command line: python -m cybercheck <command>."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cybercheck")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply database migrations")
    sub.add_parser("ingest", help="read the CT stream and store suspicious domains")
    sub.add_parser("web", help="run the dashboard")
    sub.add_parser("worker", help="run background jobs (enrichment, fetch, AI, reports, blocklist, CZDS)")
    sub.add_parser("bot", help="run the Telegram forwarding bot (long polling)")
    rp = sub.add_parser("rescore", help="re-score stored open domains with the current watchlist; drop ones that no longer match")
    rp.add_argument("--dry-run", action="store_true")
    sp = sub.add_parser("score", help="score hostnames from arguments or stdin")
    sp.add_argument("hostnames", nargs="*")
    sp.add_argument("--all", action="store_true", help="also print hostnames below the store threshold")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.cmd == "migrate":
        from .db import migrate
        applied = migrate()
        print("applied:", ", ".join(applied) if applied else "nothing (up to date)")
        return 0
    if args.cmd == "ingest":
        from . import db
        db.migrate()
        from .ingest import run
        asyncio.run(run())
        return 0
    if args.cmd == "web":
        import uvicorn
        from .config import settings
        uvicorn.run("cybercheck.web.app:app", host=settings().web_host, port=settings().web_port,
                    proxy_headers=False, log_level="info")
        return 0
    if args.cmd == "worker":
        from .worker import run
        asyncio.run(run())
        return 0
    if args.cmd == "bot":
        from . import db
        db.migrate()
        from .bot import run
        asyncio.run(run())
        return 0
    if args.cmd == "rescore":
        from .db import connect_sync, jsonb
        from .scoring import default_watchlist
        from .store import pg_unicode
        wl = default_watchlist()
        kept = dropped = changed = 0
        with connect_sync() as conn:
            rows = conn.execute("SELECT id, hostnames, score FROM domains WHERE status = 'open'").fetchall()
            for r in rows:
                hits = [h for h in (wl.score_hostname(x) for x in r["hostnames"]) if h]
                if not hits:
                    in_use = conn.execute("SELECT (SELECT count(*) FROM pages WHERE domain_id = %(i)s) + "
                                          "(SELECT count(*) FROM reports WHERE domain_id = %(i)s) AS n", {"i": r["id"]}).fetchone()["n"]
                    if not in_use:
                        dropped += 1
                        if not args.dry_run:
                            conn.execute("DELETE FROM domains WHERE id = %s", (r["id"],))
                        continue
                    kept += 1
                    continue
                best = max(hits, key=lambda h: h.score)
                kept += 1
                if best.score != r["score"]:
                    changed += 1
                if not args.dry_run:
                    conn.execute("UPDATE domains SET score = %s, tier = %s, reasons = %s, brand_id = %s WHERE id = %s",
                                 (best.score, best.tier, jsonb(pg_unicode(best.reasons)), best.brand_id, r["id"]))
        print(f"kept {kept} (score changed on {changed}), dropped {dropped}{' (dry run)' if args.dry_run else ''}")
        return 0
    if args.cmd == "score":
        from .scoring import default_watchlist
        from .store import pg_unicode
        wl = default_watchlist()
        names = args.hostnames or [line.strip() for line in sys.stdin if line.strip()]
        for name in names:
            hit = wl.score_hostname(name)
            if hit:
                print(json.dumps({"hostname": hit.hostname, "score": hit.score, "tier": hit.tier,
                                  "brand": hit.brand_id, "reasons": pg_unicode(hit.reasons)}, ensure_ascii=False))
            elif args.all:
                print(json.dumps({"hostname": name, "score": None}))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
