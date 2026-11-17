"""Re-judge pages the production model already judged, with other models, and compare.

Read-only for the pipeline: no verdict, score or page is changed. Each call goes through the normal AI client,
so the daily/monthly caps apply and every call is logged in ai_calls with purpose 'model_eval'.

    docker compose run --rm --no-deps worker python scripts/compare-models.py claude-sonnet-5-5 claude-haiku-5-5
    (or: docker exec cybercheck-worker-1 python /app/scripts/compare-models.py ...)

Options via env: COMPARE_LIMIT (default 30 pages), COMPARE_OUT (JSON results path, default data/model-eval.json).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time

from cybercheck import db
from cybercheck.ai import api, client, prompts
from cybercheck.ai.images import prepare_image
from cybercheck.jobs.judge import DOMAIN_SQL, load_screenshot

BASE_SQL = """
SELECT DISTINCT ON (a.page_id) a.page_id, a.domain_id, a.model, a.result, a.cost_usd, a.duration_ms
FROM ai_calls a
WHERE a.purpose = 'page_judge' AND a.status = 'ok' AND a.page_id IS NOT NULL AND a.result IS NOT NULL
ORDER BY a.page_id, a.at DESC
"""


async def judge_with(conn, model: str, domain: dict, page: dict, shot: bytes | None):
    img = await asyncio.to_thread(prepare_image, shot) if shot else None
    content: list[dict] = []
    if img:
        content.append({"type": "image", "source": {"type": "base64", "media_type": img.media_type, "data": img.b64}})
    content.append({"type": "text", "text": api.judge_facts(domain, page, img is not None)})
    started = time.monotonic()
    out = await client.call(conn, purpose="model_eval", system=prompts.judge_system(), content=content,
                            schema=prompts.JUDGE_SCHEMA, max_tokens=api.JUDGE_MAX_TOKENS,
                            validate=api.validate_judge, model=model, domain_id=domain.get("id"),
                            page_id=page.get("id"), image_tokens=img.tokens if img else 0)
    ms = int((time.monotonic() - started) * 1000)
    cost = None
    if out.call_id:
        row = await (await conn.execute("SELECT cost_usd FROM ai_calls WHERE id = %s", (out.call_id,))).fetchone()
        cost = float(row["cost_usd"]) if row and row["cost_usd"] is not None else None
    return {"status": out.status, "error": out.error, "ms": ms, "cost": cost,
            "verdict": (out.data or {}).get("verdict"), "confidence": (out.data or {}).get("confidence"),
            "brand": (out.data or {}).get("imitated_brand"), "explanation": (out.data or {}).get("explanation")}


async def main(models: list[str]) -> None:
    limit = int(os.environ.get("COMPARE_LIMIT", "30"))
    out_path = os.environ.get("COMPARE_OUT", "/app/data/model-eval.json")
    p = await db.pool()
    results = []
    async with p.connection() as conn:
        base = (await (await conn.execute(BASE_SQL)).fetchall())[:limit]
        for b in base:
            page = await (await conn.execute("SELECT * FROM pages WHERE id = %s", (b["page_id"],))).fetchone()
            domain = await (await conn.execute(DOMAIN_SQL, (b["domain_id"],))).fetchone()
            if not page or not domain:
                continue
            shot = await load_screenshot(page.get("screenshot_path"))
            row = {"page_id": b["page_id"], "domain": domain["registered_domain"],
                   "baseline": {"model": b["model"], "verdict": b["result"].get("verdict"),
                                "confidence": b["result"].get("confidence"), "brand": b["result"].get("imitated_brand"),
                                "cost": float(b["cost_usd"] or 0), "ms": b["duration_ms"]},
                   "models": {}}
            for m in models:
                row["models"][m] = await judge_with(conn, m, dict(domain), dict(page), shot)
                r = row["models"][m]
                print(f"{domain['registered_domain'][:40]:40} {m:18} {r['status']:9} {str(r['verdict']):10} "
                      f"{r['confidence']}  ${r['cost']}  {r['ms']}ms", flush=True)
                if r["status"] == "over_budget":
                    print("stopped: AI budget cap reached", flush=True)
                    break
            results.append(row)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=1, default=str)
    print(f"wrote {out_path} ({len(results)} pages)")
    await db.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:] or ["claude-sonnet-5-5", "claude-haiku-5-5"]))
