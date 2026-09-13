#!/usr/bin/env python3
# modules/leakcheck_api.py
# PSBDMP API - Gratis, no key, unlimited
# Ganti LeakCheck dengan PSBDMP

import os
import requests

PSBDMP_URL = "https://psbdmp.ws/api/v3/search"


def check_leakcheck(query: str, query_type: str = "email") -> dict:
    """
    Cari email/username/domain di PSBDMP (pastebin search).
    query_type: email | username | phone | domain
    PSBDMP ga bedain tipe, jadi semua tipe di-treat sama.
    Return: dict {success: bool, data: dict} atau {error: str}
    """
    if not query or len(query) < 3:
        return {"error": "Query terlalu pendek (min 3 karakter)"}

    try:
        url = f"{PSBDMP_URL}/{query}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        r = requests.get(url, headers=headers, timeout=30)

        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                return {"success": True, "data": data.get("data", [])}
            else:
                return {"success": True, "data": []}
        elif r.status_code == 404:
            return {"success": True, "data": []}
        elif r.status_code == 429:
            return {"error": "Rate limit PSBDMP. Coba lagi 1-2 menit."}
        else:
            return {"error": f"PSBDMP error: HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "PSBDMP timeout. Coba lagi."}
    except Exception as e:
        return {"error": f"PSBDMP error: {e}"}


def format_leakcheck_result(query: str, result: dict) -> str:
    """Format hasil PSBDMP jadi text rapi buat Telegram."""
    if "error" in result:
        return f"❌ *Error:* {result['error']}"

    data = result.get("data", [])
    if not data:
        return f"✅ *{query}* ga ditemukan di pastebin (PSBDMP)."

    found = len(data)

    text = f"🚨 *HASIL PSBDMP*\n\n"
    text += f"📧 *Query:* `{query}`\n"
    text += f"📊 *Ditemukan di:* `{found}` paste\n\n"

    text += f"*Daftar Paste:*\n"
    for i, entry in enumerate(data[:10], 1):
        if isinstance(entry, dict):
            paste_id = entry.get("id", "unknown")
            paste_time = entry.get("time", "")
            paste_text = entry.get("text", "")
            paste_tags = entry.get("tags", [])

            # Preview text (max 100 char)
            preview = paste_text[:100].replace("\n", " ").replace("`", "")
            if len(paste_text) > 100:
                preview += "..."

            text += f"\n*{i}.* `{paste_id}`\n"
            if paste_time:
                text += f"   📅 `{paste_time}`\n"
            if paste_tags:
                text += f"   🏷️ `{', '.join(paste_tags[:3])}`\n"
            if preview:
                text += f"   📝 _{preview}_\n"
            text += f"   🔗 `https://pastebin.com/{paste_id}`\n"

    if found > 10:
        text += f"\n_... dan {found - 10} paste lainnya_\n"

    text += f"\n🔒 _Buat edukasi. Jangan disalahgunain._"
    return text
