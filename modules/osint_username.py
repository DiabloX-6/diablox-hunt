import requests
from concurrent.futures import ThreadPoolExecutor

SITES = {
    "github":    "https://github.com/{}",
    "instagram": "https://instagram.com/{}",
    "twitter":   "https://twitter.com/{}",
    "facebook":  "https://facebook.com/{}",
    "tiktok":    "https://tiktok.com/@{}",
    "reddit":    "https://reddit.com/user/{}",
    "youtube":   "https://youtube.com/@{}",
    "pinterest": "https://pinterest.com/{}",
    "telegram":  "https://t.me/{}",
    "linkedin":  "https://linkedin.com/in/{}",
    "gitlab":    "https://gitlab.com/{}",
    "medium":    "https://medium.com/@{}",
    "twitch":    "https://twitch.tv/{}",
    "steam":     "https://steamcommunity.com/id/{}",
    "spotify":   "https://open.spotify.com/user/{}",
}

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

def _check(site, url, user):
    try:
        r = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
        if r.status_code == 200 and "not found" not in r.text.lower()[:2000]:
            return f"✅ `{site}` → {url}"
    except Exception:
        pass
    return None

def scan_username(username: str) -> str:
    results = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(_check, s, u.format(username), username) for s, u in SITES.items()]
        for f in futures:
            r = f.result()
            if r:
                results.append(r)
    if not results:
        return f"🔍 *Username: {username}*\n\n_Tidak ditemukan di platform manapun._"
    return f"🔍 *Username: {username}*\n\n" + "\n".join(results)
