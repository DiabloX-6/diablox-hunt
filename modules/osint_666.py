"""
osint_extra.py — tambahan modul OSINT gratis
"""
import httpx
import re


async def scan_github(username: str) -> str:
    try:
        r = httpx.get(
            f"https://api.github.com/users/{username}",
            headers={"User-Agent": "DiabloX-Hunt"},
            timeout=10
        )
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
        return f"❌ {e}"


async def scan_cert(domain: str) -> str:
    try:
        r = httpx.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20
        )
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
        return text
    except Exception as e:
        return f"❌ {e}"


async def scan_pastebin(keyword: str) -> str:
    try:
        r = httpx.get(
            f"https://psbdmp.ws/api/search/{keyword}",
            timeout=10
        )
        if r.status_code != 200:
            return f"⚠️ psbdmp error {r.status_code}"
        data = r.json()
        if not isinstance(data, dict) or not data.get("data"):
            return f"📭 Gak ada hasil di Pastebin untuk `{keyword}`"
        text = f"📋 *Pastebin: {keyword}*\n\n"
        for item in data["data"][:10]:
            text += f"• `{item.get('id')}` — {item.get('time', '')[:10]}\n"
        return text
    except Exception as e:
        return f"❌ {e}"


async def scan_tiktok(username: str) -> str:
    """Cek profil TikTok publik via scraping meta."""
    try:
        r = httpx.get(
            f"https://www.tiktok.com/@{username}",
            headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 13) "
                              "AppleWebKit/537.36 Chrome/122.0 Mobile"
            },
            timeout=15,
            follow_redirects=True
        )
        if r.status_code != 200:
            return f"❌ TikTok user `{username}` gak ada / diblokir."
        html = r.text
        # meta og
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
        return f"❌ {e}"
