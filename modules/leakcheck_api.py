#!/usr/bin/env python3
# modules/leakcheck_api.py
# Integrasi LeakCheck.io API v2

import os
import requests

LEAKCHECK_KEY = os.getenv("LEAKCHECK_KEY", "")
LEAKCHECK_URL = "https://leakcheck.io/api/v2/query"


def check_leakcheck(query: str, query_type: str = "email") -> dict:
    """
    Cek email/username/phone/domain di LeakCheck.
    query_type: email | username | phone | domain
    Return: dict {success: bool, data: dict} atau {error: str}
    """
    if not LEAKCHECK_KEY:
        return {"error": "LEAKCHECK_KEY belum di-set di .env"}

    headers = {
        "X-API-Key": LEAKCHECK_KEY,
        "Accept": "application/json",
    }
    params = {
        "check": query,
        "type": query_type,
    }

    try:
        r = requests.get(LEAKCHECK_URL, headers=headers, params=params, timeout=30)
        if r.status_code == 200:
            data = r.json()
            return {"success": True, "data": data}
        elif r.status_code == 401:
            return {"error": "API key LeakCheck invalid. Cek di leakcheck.io/dashboard"}
        elif r.status_code == 429:
            return {"error": "Rate limit LeakCheck (100 query/hari di free tier). Coba besok."}
        elif r.status_code == 403:
            return {"error": "Akses ditolak. Paket free cuma bisa email/username/phone basic."}
        else:
            return {"error": f"LeakCheck error: HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "LeakCheck timeout. Coba lagi."}
    except Exception as e:
        return {"error": f"LeakCheck error: {e}"}


def format_leakcheck_result(query: str, result: dict) -> str:
    """Format hasil LeakCheck jadi text rapi buat Telegram."""
    if "error" in result:
        return f"❌ *Error:* {result['error']}"

    data = result.get("data", {})
    if not data:
        return f"✅ *{query}* tidak ditemukan di database leak."

    found = data.get("found", 0)
    sources = data.get("sources", [])
    fields = data.get("fields", [])
    result_list = data.get("result", [])

    if found == 0:
        return f"✅ *{query}* tidak ditemukan di database leak."

    text = f"🚨 *HASIL LEAKCHECK*\n\n"
    text += f"📧 *Query:* `{query}`\n"
    text += f"📊 *Ditemukan di:* `{found}` breach\n\n"

    # Sources
    if sources:
        text += f"*Sumber Breach:*\n"
        for src in sources[:15]:
            if isinstance(src, dict):
                name = src.get("name", "Unknown")
                date = src.get("date", "")
                text += f"  • `{name}`"
                if date:
                    text += f" ({date})"
                text += "\n"
            else:
                text += f"  • `{src}`\n"
        if len(sources) > 15:
            text += f"  _... dan {len(sources)-15} sumber lainnya_\n"
        text += "\n"

    # Fields
    if fields:
        text += f"*Data yang bocor:* `{', '.join(fields)}`\n\n"

    # Detail entries
    if result_list:
        text += f"*Detail (max 10):*\n"
        for i, entry in enumerate(result_list[:10]):
            if isinstance(entry, dict):
                # Format: email:password atau field lain
                parts = []
                for k in ["email", "username", "password", "name", "phone", "hash", "ip"]:
                    if entry.get(k):
                        parts.append(f"{k}=`{entry[k]}`")
                if parts:
                    text += f"  • " + " | ".join(parts) + "\n"
        if len(result_list) > 10:
            text += f"  _... dan {len(result_list)-10} entry lainnya_\n"
        text += "\n"

    text += f"🔒 _Buat edukasi. Jangan disalahgunain._"
    return text
