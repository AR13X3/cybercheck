"""Prepare a page screenshot for the vision check: bounded size, known media type, token estimate."""
from __future__ import annotations

import base64
import io
import logging
import math
from dataclasses import dataclass

log = logging.getLogger("cybercheck.ai")

MAX_SOURCE_PIXELS = 25_000_000   # refuse to decode anything bigger (memory on a shared server)
MAX_SOURCE_BYTES = 15_000_000
MAX_HEIGHT = 2400                # tall full-page shots: keep the top, where sign-in forms are
MAX_LONG_EDGE = 1920
MAX_PIXELS = 1_800_000           # ~2,400 image tokens at most
MAX_SEND_BYTES = 3_500_000       # API limit is 5 MB per image after base64
MEDIA = {"WEBP": "image/webp", "PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif"}


@dataclass
class PreparedImage:
    media_type: str
    b64: str
    width: int
    height: int
    tokens: int


def image_tokens(width: int, height: int) -> int:
    return min(4784, math.ceil(width * height / 750)) + 20


def prepare_image(data: bytes) -> PreparedImage | None:
    """Returns None when the bytes are not a usable image (the judge then runs on text alone)."""
    if not data or len(data) > MAX_SOURCE_BYTES:
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            fmt = (im.format or "").upper()
            w, h = im.size
            if w < 16 or h < 16 or w * h > MAX_SOURCE_PIXELS:
                return None
            out = im
            changed = False
            if h > MAX_HEIGHT:
                out = out.crop((0, 0, w, MAX_HEIGHT))
                h = MAX_HEIGHT
                changed = True
            scale = min(1.0, MAX_LONG_EDGE / max(w, h), math.sqrt(MAX_PIXELS / (w * h)))
            if scale < 1.0:
                w, h = max(1, round(w * scale)), max(1, round(h * scale))
                out = out.resize((w, h), Image.Resampling.LANCZOS)
                changed = True
            if changed or fmt not in MEDIA or len(data) > MAX_SEND_BYTES:
                if out.mode not in ("RGB", "RGBA"):
                    out = out.convert("RGBA" if "A" in out.mode or "transparency" in out.info else "RGB")
                buf = io.BytesIO()
                out.save(buf, format="WEBP", quality=80, method=4)
                payload, media = buf.getvalue(), "image/webp"
            else:
                payload, media = data, MEDIA[fmt]
        if len(payload) > MAX_SEND_BYTES:
            return None
        return PreparedImage(media, base64.standard_b64encode(payload).decode("ascii"), w, h, image_tokens(w, h))
    except Exception as e:
        log.warning("screenshot could not be used for the AI check: %s", type(e).__name__)
        return None
