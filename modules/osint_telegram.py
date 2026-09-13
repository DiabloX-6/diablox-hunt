import requests, re

def scan_telegram(target: str) -> str:
    target = target.lstrip("@")
    try:
        if target.isdigit():
            return f"🆔 *Telegram ID numeric*: `{target}`\n_Gunakan @userinfobot untuk resolve._"
        r = requests.get(f"https://t.me/{target}", timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return f"❌ @{target} tidak ditemukan."
        html = r.text
        title = re.search(r'<meta property="og:title" content="([^"]+)"', html)
        desc = re.search(r'<meta property="og:description" content="([^"]+)"', html)
        return (
            f"💬 *Telegram: @{target}*\n\n"
            f"📛 *Name*: `{title.group(1) if title else '-'}`\n"
            f"📝 *Bio*: `{desc.group(1) if desc else '-'}`"
        )
    except Exception as e:
        return f"❌ Error: {e}"
