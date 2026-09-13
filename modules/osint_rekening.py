"""
osint_rekening.py
Modul OSINT cek rekening — BRUTAL EDITION (sync drop-in)
Owner: Naddd | DiabloX Hunt

Fitur:
- Multi-endpoint paralel + retry
- UA rotation
- Cache TTL + persist disk
- Multi-parser (JSON / HTML / plain)
- Normalisasi output: nama, bank, status
- Batch scan (scan_batch)

Kompatibel dengan bot.py yang panggil:
    scan_rekening(norek: str) -> str
via asyncio.to_thread.
"""

import re
import json
import time
import random
import logging
from pathlib import Path
from typing import Optional

import httpx
from cachetools import TTLCache

log = logging.getLogger(__name__)

# =========================================================
#  CACHE (TTL 10 menit, persist disk)
# =========================================================
_cache: TTLCache = TTLCache(maxsize=1000, ttl=600)
_CACHE_FILE = Path("cache_rekening.json")


def _load_cache():
    if _CACHE_FILE.exists():
        try:
            data = json.loads(_CACHE_FILE.read_text())
            for k, v in data.items():
                _cache[k] = v
        except Exception:
            pass


def _save_cache():
    try:
        _CACHE_FILE.write_text(json.dumps(dict(_cache), ensure_ascii=False))
    except Exception:
        pass


# =========================================================
#  ENDPOINT SUMBER
# =========================================================
# Format: (url_template, tipe, method)
# tipe: "auto" | "json" | "html"
# Tambahin sumber lain di sini kalau kau punya.
ENDPOINTS = [
    ("https://cekrekening.github.io/api/{norek}", "auto", "GET"),
]


# =========================================================
#  HEADERS ROTATION
# =========================================================
UAS = [
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def _headers() -> dict:
    return {
        "User-Agent": random.choice(UAS),
        "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "id-ID,id;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


TIMEOUT = httpx.Timeout(12.0, connect=5.0)
RETRY = 3


# =========================================================
#  VALIDASI
# =========================================================
def _clean(norek: str) -> str:
    return re.sub(r"[\s\-\.]", "", norek or "")


def _valid(norek: str) -> Optional[str]:
    if not norek:
        return "❌ Rekening kosong."
    if not norek.isdigit():
        return "❌ Rekening hanya boleh angka."
    if not (8 <= len(norek) <= 20):
        return "❌ Panjang rekening tidak wajar (8–20 digit)."
    return None


# =========================================================
#  PARSER MULTI-FORMAT
# =========================================================
def _parse(text: str) -> Optional[dict]:
    text = (text or "").strip()
    if not text:
        return None

    out = {"nama": None, "bank": None, "status": None, "raw": text[:1000]}

    # --- JSON ---
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
            flat = data if isinstance(data, dict) else {"data": data}
            for key, val in flat.items():
                k = key.lower()
                if any(x in k for x in ("nama", "name", "owner", "pemilik")):
                    out["nama"] = str(val)
                elif any(x in k for x in ("bank", "provider", "e-wallet", "ewallet")):
                    out["bank"] = str(val)
                elif "status" in k:
                    out["status"] = str(val)
            if not out["nama"] and isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, str) and 3 < len(v) < 60:
                        out["nama"] = v
                        break
            return out
        except Exception:
            pass

    # --- HTML / plain ---
    clean = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    clean = re.sub(r"<style.*?</style>", " ", clean, flags=re.S | re.I)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    m = re.search(r"\b([A-Z][A-Z' ]{3,60})\b", clean)
    if m:
        out["nama"] = m.group(1).strip()

    low = clean.lower()
    if "tidak ditemukan" in low or "not found" in low:
        out["status"] = "not_found"
    elif "berhasil" in low or "success" in low:
        out["status"] = "ok"

    out["raw"] = clean[:1000]
    return out


# =========================================================
#  FETCH SATU SUMBER (sync)
# =========================================================
def _fetch_one(url: str, tipe: str, method: str) -> Optional[dict]:
    for attempt in range(RETRY):
        try:
            with httpx.Client(
                headers=_headers(),
                timeout=TIMEOUT,
                follow_redirects=True,
            ) as client:
                if method == "POST":
                    r = client.post(url)
                else:
                    r = client.get(url)

                if r.status_code == 200:
                    return _parse(r.text)
                if r.status_code == 404:
                    return {"_err": "404"}
                if r.status_code == 429:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                if 500 <= r.status_code < 600:
                    time.sleep(0.5)
                    continue
                return {"_err": f"HTTP {r.status_code}"}
        except httpx.TimeoutException:
            continue
        except httpx.ConnectError:
            continue
        except Exception as e:
            return {"_err": f"{type(e).__name__}: {e}"}
    return {"_err": "retry habis"}


# =========================================================
#  MAIN: scan_rekening (SYNC — dipanggil via asyncio.to_thread)
# =========================================================
def scan_rekening(norek: str) -> str:
    """
    Cek rekening bank / e-wallet.
    Return string siap kirim ke Telegram (Markdown).
    Sinkron — kompatibel dengan asyncio.to_thread.
    """
    norek = _clean(norek)
    err = _valid(norek)
    if err:
        return err

    # cache
    if norek in _cache:
        log.info("cache hit: %s", norek)
        return _cache[norek]

    if not ENDPOINTS:
        return "⚠️ Tidak ada endpoint yang dikonfigurasi."

    best = None
    errors = []

    for url_tpl, tipe, method in ENDPOINTS:
        url = url_tpl.format(norek=norek)
        res = _fetch_one(url, tipe, method)

        if not res:
            errors.append(f"{url_tpl}: empty")
            continue
        if "_err" in res:
            errors.append(f"{url_tpl}: {res['_err']}")
            continue
        if res.get("nama") or res.get("bank") or res.get("status") == "ok":
            best = (url_tpl, res)
            break
        if best is None:
            best = (url_tpl, res)

    if best is None:
        return (
            f"⚠️ *Semua sumber gagal.*\n"
            f"Rekening: `{norek}`\n\n"
            f"```\n" + "\n".join(errors[:5]) + "\n```"
        )

    url_tpl, data = best

    lines = [f"🏦 *Cek Rekening:* `{norek}`"]
    if data.get("nama"):
        lines.append(f"👤 *Nama:* {data['nama']}")
    if data.get("bank"):
        lines.append(f"🏛 *Bank:* {data['bank']}")
    if data.get("status"):
        lines.append(f"📌 *Status:* {data['status']}")
    lines.append(f"🌐 *Sumber:* `{url_tpl}`")

    if data.get("raw"):
        lines.append(f"\n```\n{data['raw'][:800]}\n```")

    hasil = "\n".join(lines)
    _cache[norek] = hasil
    _save_cache()
    return hasil


# =========================================================
#  BATCH SCAN (opsional, kalau handler mau pakai)
# =========================================================
def scan_batch(noreks: list) -> list:
    """Scan banyak rekening. Return list of (norek, hasil)."""
    out = []
    for n in noreks:
        try:
            out.append((n, scan_rekening(n)))
        except Exception as e:
            out.append((n, f"❌ {e}"))
    return out


# =========================================================
#  INIT
# =========================================================
_load_cache()
