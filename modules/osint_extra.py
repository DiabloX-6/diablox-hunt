"""
osint_extra.py — modul OSINT tambahan
Owner: Naddd | DiabloX Hunt
"""
import os
import io
import re
import json
import httpx
import logging
from typing import Optional

log = logging.getLogger(__name__)

SECURITYTRAILS_KEY = os.getenv("SECURITYTRAILS_KEY", "")
LEAKCHECK_KEY = os.getenv("LEAKCHECK_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")

UA = ("Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36")


# =========================================================
#  /pastebin — psbdmp.ws (gratis)
# =========================================================
async def scan_pastebin(keyword: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": UA}) as c:
            r = await c.get(f"https://psbdmp.ws/api/search/{keyword}")
        if r.status_code != 200:
            return f"⚠️ psbdmp error {r.status_code}"
        try:
            data = r.json()
        except Exception:
            return "❌ Respon bukan JSON."
        items = data.get("data") if isinstance(data, dict) else None
        if not items:
            return f"📭 Gak ada hasil Pastebin untuk `{keyword}`"
        text = f"📋 *Pastebin: {keyword}*\nTotal: *{len(items)}*\n\n"
        for item in items[:10]:
            pid = item.get("id", "?")
            tgl = (item.get("time") or "")[:10]
            text += f"• `{pid}` — {tgl}\n   https://pastebin.com/{pid}\n"
        if len(items) > 10:
            text += f"\n_... dan {len(items)-10} lainnya_"
        return text
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


# =========================================================
#  /exif — metadata foto
# =========================================================
async def scan_exif(url: str) -> str:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return "❌ Modul `Pillow` belum diinstall. `pip install Pillow`"

    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": UA},
                                     follow_redirects=True) as c:
            r = await c.get(url)
        if r.status_code != 200:
            return f"❌ Gagal download: HTTP {r.status_code}"
        if len(r.content) > 15 * 1024 * 1024:
            return "❌ File terlalu besar (>15MB)."

        img = Image.open(io.BytesIO(r.content))
        text = (
            f"🖼 *EXIF Metadata*\n"
            f"📐 Ukuran: `{img.size[0]}x{img.size[1]}`\n"
            f"🎨 Mode: `{img.mode}`\n"
            f"📦 Format: `{img.format}`\n\n"
        )

        exif = img.getexif()
        if not exif:
            return text + "_Tidak ada EXIF metadata._"

        found = False
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                continue
            text += f"• *{tag}:* `{str(value)[:100]}`\n"
            found = True

        gps_info = exif.get_ifd(0x8825)
        if gps_info:
            gps = {}
            for k, v in gps_info.items():
                gps[GPSTAGS.get(k, k)] = v
            if "GPSLatitude" in gps and "GPSLongitude" in gps:
                def to_deg(v):
                    d, m, s = v
                    return float(d) + float(m) / 60 + float(s) / 3600
                lat = to_deg(gps["GPSLatitude"])
                lon = to_deg(gps["GPSLongitude"])
                if gps.get("GPSLatitudeRef") == "S": lat = -lat
                if gps.get("GPSLongitudeRef") == "W": lon = -lon
                text += f"\n📍 *GPS:* `{lat}, {lon}`\n"
                text += f"🗺 https://maps.google.com/?q={lat},{lon}\n"
                found = True

        if not found:
            text += "\n_Tidak ada metadata berarti._"
        return text[:4000]
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


# =========================================================
#  /shodand — Shodan domain scan
# =========================================================
async def scan_shodan_domain(domain: str) -> str:
    if not SHODAN_KEY:
        return "❌ `SHODAN_API_KEY` belum di-set di env."
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": UA}) as c:
            r = await c.get(
                f"https://api.shodan.io/dns/domain/{domain}",
                params={"key": SHODAN_KEY}
            )
        if r.status_code == 401:
            return "❌ Shodan API key invalid."
        if r.status_code == 404:
            return f"📭 Domain `{domain}` gak ada di Shodan."
        if r.status_code != 200:
            return f"⚠️ Shodan error {r.status_code}"
        d = r.json()
        subs = d.get("subdomains", [])
        records = d.get("data", [])
        text = f"🔭 *Shodan Domain: {domain}*\n"
        text += f"🌐 Subdomain: *{len(subs)}*\n"
        text += f"📋 Records: *{len(records)}*\n\n"
        for s in subs[:20]:
            text += f"• `{s}.{domain}`\n"
        if len(subs) > 20:
            text += f"_... dan {len(subs)-20} lainnya_\n"
        if records:
            text += "\n*DNS Records:*\n"
            for rec in records[:15]:
                t = rec.get("type", "?")
                v = rec.get("value", "?")
                text += f"• `{t}` → `{v}`\n"
        return text[:4000]
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


# =========================================================
#  /subhist — subdomain history (SecurityTrails)
# =========================================================
async def scan_subdomain_history(domain: str) -> str:
    if not SECURITYTRAILS_KEY:
        return (
            "⚠️ Butuh API key `SECURITYTRAILS_KEY`.\n"
            "Daftar gratis di https://securitytrails.com (50 query/bln)."
        )
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": UA}) as c:
            r = await c.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                params={"children_only": "false", "include_inactive": "true"},
                headers={"APIKEY": SECURITYTRAILS_KEY, "Accept": "application/json"}
            )
        if r.status_code == 401:
            return "❌ SecurityTrails API key invalid."
        if r.status_code != 200:
            return f"⚠️ SecurityTrails error {r.status_code}"
        d = r.json()
        subs = d.get("subdomains", [])
        if not subs:
            return f"📭 Gak ada subdomain untuk `{domain}`"
        text = f"📜 *Subdomain History: {domain}*\nTotal: *{len(subs)}*\n\n"
        for s in subs[:40]:
            text += f"• `{s}.{domain}`\n"
        if len(subs) > 40:
            text += f"\n_... dan {len(subs)-40} lainnya_"
        return text[:4000]
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


# =========================================================
#  /leakcheck — LeakCheck.io
# =========================================================
async def scan_leakcheck(keyword: str) -> str:
    if not LEAKCHECK_KEY:
        return (
            "⚠️ Butuh API key `LEAKCHECK_KEY`.\n"
            "Daftar di https://leakcheck.io (bayar).\n"
            f"Alternatif gratis: `/pastebin {keyword}`"
        )
    try:
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": UA}) as c:
            r = await c.get(
                "https://leakcheck.io/api/public",
                params={"key": LEAKCHECK_KEY, "check": keyword},
                headers={"Accept": "application/json"}
            )
        if r.status_code == 401:
            return "❌ LeakCheck API key invalid."
        if r.status_code == 429:
            return "⚠️ Rate limit LeakCheck. Coba lagi nanti."
        if r.status_code != 200:
            return f"⚠️ LeakCheck error {r.status_code}"
        d = r.json()
        if not d.get("success"):
            return f"📭 `{keyword}` gak ditemukan di database kebocoran."
        sources = d.get("sources", [])
        text = (
            f"🚨 *LeakCheck: {keyword}*\n"
            f"📊 Total kebocoran: *{len(sources)}*\n\n"
        )
        for s in sources[:15]:
            text += f"• *{s.get('name', '?')}* ({s.get('date', '?')})\n"
        if len(sources) > 15:
            text += f"\n_... dan {len(sources)-15} lainnya_"
        return text[:4000]
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


# =========================================================
#  /phonetrack — analisis nomor HP
# =========================================================
async def scan_phonetrack(nomor: str) -> str:
    nomor = re.sub(r"[^\d+]", "", nomor)
    if not nomor.startswith("+"):
        if nomor.startswith("0"):
            nomor = "+62" + nomor[1:]
        elif nomor.startswith("62"):
            nomor = "+" + nomor

    text = f"📱 *Phone Track: {nomor}*\n\n"
    text += _deteksi_operator_id(nomor) + "\n"

    if NUMVERIFY_KEY:
        try:
            async with httpx.AsyncClient(timeout=15, headers={"User-Agent": UA}) as c:
                r = await c.get(
                    "http://apilayer.net/api/validate",
                    params={
                        "access_key": NUMVERIFY_KEY,
                        "number": nomor,
                        "country_code": "",
                        "format": 1
                    }
                )
            if r.status_code == 200:
                d = r.json()
                if d.get("valid"):
                    text += "\n*NumVerify:*\n"
                    text += f"• Negara: `{d.get('country_name', '-')}`\n"
                    text += f"• Lokasi: `{d.get('location', '-')}`\n"
                    text += f"• Carrier: `{d.get('carrier', '-')}`\n"
                    text += f"• Line type: `{d.get('line_type', '-')}`\n"
        except Exception as e:
            text += f"\n_NumVerify error: {e}_\n"
    else:
        text += "\n_NumVerify off — set `NUMVERIFY_KEY` untuk info lebih._\n"

    text += "\n*Cek publik:*\n"
    text += f"• https://www.truecaller.com/search/id/{nomor.lstrip('+')}\n"
    text += f"• https://wa.me/{nomor.lstrip('+')}\n"

    return text


def _deteksi_operator_id(nomor: str) -> str:
    n = nomor.lstrip("+")
    if n.startswith("62"):
        n = "0" + n[2:]
    prefix4 = n[:4]

    operator_map = {
        "0811": "Telkomsel (Halo)", "0812": "Telkomsel", "0813": "Telkomsel",
        "0821": "Telkomsel", "0822": "Telkomsel", "0823": "Telkomsel",
        "0851": "Telkomsel", "0852": "Telkomsel", "0853": "Telkomsel",
        "0814": "Indosat", "0815": "Indosat", "0816": "Indosat",
        "0855": "Indosat", "0856": "Indosat", "0857": "Indosat",
        "0858": "Indosat",
        "0817": "XL", "0818": "XL", "0819": "XL",
        "0859": "XL", "0877": "XL", "0878": "XL",
        "0831": "Axis", "0832": "Axis", "0833": "Axis", "0838": "Axis",
        "0895": "Tri", "0896": "Tri", "0897": "Tri", "0898": "Tri", "0899": "Tri",
        "0881": "Smartfren", "0882": "Smartfren", "0883": "Smartfren",
        "0884": "Smartfren", "0885": "Smartfren", "0886": "Smartfren",
        "0887": "Smartfren", "0888": "Smartfren", "0889": "Smartfren",
    }
    op = operator_map.get(prefix4, "Tidak diketahui")
    return f"🏢 *Operator:* `{op}`"


# =========================================================
#  Extra: GitHub, Cert, TikTok (kalau ada di bot.py lama)
# =========================================================
async def scan_github(username: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": UA}) as c:
            r = await c.get(f"https://api.github.com/users/{username}")
        if r.status_code == 404:
            return f"❌ User GitHub `{username}` gak ditemukan."
        if r.status_code != 200:
            return f"⚠️ GitHub API error {r.status_code}"
        d = r.json()
        return (
            f"🐙 *GitHub: {d['login']}*\n"
            f"👤 Nama: {d.get('name') or '-'}\n"
            f"📝 Bio: {d.get('bio') or '-'}\n"
            f"📍 Lokasi: {d.get('location') or '-'}\n"
            f"🏢 Company: {d.get('company') or '-'}\n"
            f"📧 Email: `{d.get('email') or '-'}`\n"
            f"🔗 Blog: {d.get('blog') or '-'}\n"
            f"📦 Repo: {d['public_repos']}\n"
            f"👥 Followers: {d['followers']}\n"
            f"📅 Join: {d['created_at'][:10]}"
        )
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


async def scan_cert(domain: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=25, headers={"User-Agent": UA}) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.status_code != 200:
            return f"⚠️ crt.sh error {r.status_code}"
        data = r.json()
        subs = set()
        for item in data:
            for name in item.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(domain) and "*" not in name:
                    subs.add(name)
        if not subs:
            return f"📭 Tidak ada subdomain dari crt.sh untuk `{domain}`"
        text = f"🔒 *Subdomain (crt.sh): {domain}*\nTotal: *{len(subs)}*\n\n"
        for s in sorted(subs)[:50]:
            text += f"• `{s}`\n"
        if len(subs) > 50:
            text += f"\n_... dan {len(subs)-50} lainnya_"
        return text[:4000]
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"


async def scan_tiktok(username: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": UA},
                                     follow_redirects=True) as c:
            r = await c.get(f"https://www.tiktok.com/@{username}")
        if r.status_code != 200:
            return f"❌ TikTok user `{username}` gak ada / diblokir."
        html = r.text
        nama = re.search(r'"nickname":"([^"]+)"', html)
        bio = re.search(r'"signature":"([^"]*)"', html)
        fol = re.search(r'"followerCount":(\d+)', html)
        video = re.search(r'"videoCount":(\d+)', html)
        text = f"📱 *TikTok: @{username}*\n"
        if nama: text += f"👤 Nama: {nama.group(1)}\n"
        if bio: text += f"📝 Bio: {bio.group(1)}\n"
        if fol: text += f"👥 Followers: {fol.group(1)}\n"
        if video: text += f"🎬 Video: {video.group(1)}\n"
        if text.count("\n") <= 1:
            text += "_Data terbatas (kemungkinan diblokir)._\n"
        return text
    except Exception as e:
        return f"❌ {type(e).__name__}: {e}"
