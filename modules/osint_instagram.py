import requests, re

def scan_ig(username: str) -> str:
    username = username.lstrip("@")
    url = f"https://www.instagram.com/{username}/"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return f"❌ IG @{username}: status {r.status_code}"
        html = r.text
        desc = re.search(r'<meta property="og:description" content="([^"]+)"', html)
        title = re.search(r'<meta property="og:title" content="([^"]+)"', html)
        img = re.search(r'<meta property="og:image" content="([^"]+)"', html)
        return (
            f"📸 *Instagram: @{username}*\n"
            f"🔗 `{url}`\n\n"
            f"📛 *Title*: `{title.group(1) if title else '-'}`\n"
            f"📝 *Bio*: `{desc.group(1) if desc else '-'}`\n"
            f"🖼️ *Avatar*: `{img.group(1) if img else '-'}`"
        )
    except Exception as e:
        return f"❌ Error: {e}"
