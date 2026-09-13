#!/usr/bin/env python3
# modules/leak_agg.py
# Leak Aggregator v2 - rotasi proxy + multithread + filter false positive
# Requirements: pip install requests beautifulsoup4 lxml fake-useragent

import os
import re
import json
import time
import random
import threading
from queue import Queue
from urllib.parse import urljoin, urlparse
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# ============ KONFIGURASI ============
THREADS = 20
TIMEOUT = 15
MAX_RETRY = 3
OUTPUT_DIR = os.getenv("LEAK_OUTPUT_DIR", "reports/leak")

# ============ PROXY LIST ============
PROXY_LIST = [p.strip() for p in os.getenv("PROXY_LIST", "").split(",") if p.strip()]


def fetch_free_proxies():
    proxies = []
    try:
        r = requests.get(
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            timeout=10)
        if r.status_code == 200:
            for line in r.text.strip().split("\n"):
                line = line.strip()
                if line and ":" in line:
                    proxies.append(f"http://{line}")
    except Exception:
        pass
    try:
        r = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", timeout=10)
        if r.status_code == 200:
            for line in r.text.strip().split("\n"):
                line = line.strip()
                if line and ":" in line:
                    proxies.append(f"http://{line}")
    except Exception:
        pass
    return list(set(proxies))


try:
    from fake_useragent import UserAgent
    _ua = UserAgent()
    def get_ua():
        return _ua.random
except Exception:
    _UA_LIST = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0",
    ]
    def get_ua():
        return random.choice(_UA_LIST)


class ProxyRotator:
    def __init__(self, proxies):
        self.proxies = proxies
        self.lock = threading.Lock()
        self.failed = set()

    def get(self):
        with self.lock:
            available = [p for p in self.proxies if p not in self.failed]
            if not available:
                return None
            proxy = random.choice(available)
            return {"http": proxy, "https": proxy}

    def mark_failed(self, proxy_dict):
        if not proxy_dict:
            return
        with self.lock:
            for v in proxy_dict.values():
                self.failed.add(v)


# ============ PATTERN DETEKSI (LEBIH KETAT) ============
PATTERNS = {
    # Email: harus ada TLD valid, minimal 2 karakter
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",

    # Password: HANYA format user:pass atau password=value dengan value minimal 6 char
    # dan ada minimal 1 angka atau simbol (biar bukan kata biasa)
    "password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([a-zA-Z0-9!@#$%^&*_\-]{6,32})['\"]?",

    # user:pass format (common di dump)
    "user_pass": r"\b[a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*_\-]{6,32}\b",

    # Hash dengan format yang jelas
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha1": r"\b[a-fA-F0-9]{40}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "hash_bcrypt": r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}",

    # Credit card: harus 13-19 digit, biasanya diawali 4/5/3/6
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",

    # IP: exclude private range dan localhost
    "public_ip": r"\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.|0\.|255\.)(?:\d{1,3}\.){3}\d{1,3}\b",

    # BTC wallet
    "btc_wallet": r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",

    # ETH wallet
    "eth_wallet": r"\b0x[a-fA-F0-9]{40}\b",

    # Private key
    "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",

    # API key: lebih spesifik, minimal 20 char
    "api_key": r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,64})['\"]?",

    # AWS credentials
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",

    # JWT token
    "jwt": r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",

    # Database connection string
    "db_conn": r"(?i)(?:mysql|postgres|postgresql|mongodb|redis):\/\/[^\s]+:[^\s]+@[^\s]+",

    # Telegram bot token
    "tg_token": r"\b\d{8,10}:[a-zA-Z0-9_-]{35}\b",
}

# ============ SUMBER TARGET (FOKUS PASTE SITE) ============
SOURCES = {
    "pastebin_archive": "https://pastebin.com/archive",
    "pastebin_trending": "https://pastebin.com/trends",
    "rentry": "https://rentry.co/",
    "dpaste": "https://dpaste.com/",
}

# ============ SKIP PATTERNS (URL yang ga relevan) ============
SKIP_URL_KEYWORDS = [
    "/help", "/about", "/faq", "/docs", "/documentation",
    "/terms", "/privacy", "/contact", "/login", "/register",
    "/signup", "/signin", "/pricing", "/blog", "/news",
    "/cookie", "/legal", "/tos", "/dmca", "/report",
    "/api/", "/static/", "/assets/", "/css/", "/js/",
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map",
]


def should_skip_url(url):
    """Skip URL yang ga relevan (halaman statis, dokumentasi, dll)."""
    url_lower = url.lower()
    return any(kw in url_lower for kw in SKIP_URL_KEYWORDS)


def fetch(url, rotator, retry=MAX_RETRY):
    for _ in range(retry):
        proxy = rotator.get() if rotator else None
        headers = {
            "User-Agent": get_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        try:
            r = requests.get(url, headers=headers, proxies=proxy, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200:
                return r.text
            elif r.status_code in (403, 429):
                if proxy and rotator:
                    rotator.mark_failed(proxy)
                time.sleep(random.uniform(1, 3))
        except Exception:
            if proxy and rotator:
                rotator.mark_failed(proxy)
            time.sleep(random.uniform(0.5, 2))
    return None


def scrape_links(source_name, url, rotator):
    html = fetch(url, rotator)
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    links = []
    base = "https://" + url.split("//")[1].split("/")[0]
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if any(x in href for x in ["/raw/", "/paste/", "/view/", "/show/", "/download/"]):
            links.append(urljoin(base, href))
        elif source_name == "pastebin_archive" and href.startswith("/") and len(href) == 9:
            links.append(urljoin(base, href))
        elif source_name == "rentry" and href.startswith("/") and len(href) > 1 and ":" not in href:
            links.append(urljoin(base, href))
    if not links:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") and len(href) > 2:
                links.append(urljoin(base, href))
    # Filter URL yang ga relevan
    links = [l for l in set(links) if not should_skip_url(l)]
    return links[:100]


def extract_patterns(text):
    """Extract pattern dengan filter false positive."""
    results = {}
    for name, pattern in PATTERNS.items():
        try:
            matches = re.findall(pattern, text)
            if matches:
                flat = []
                for m in matches:
                    if isinstance(m, tuple):
                        flat.extend([x for x in m if x])
                    else:
                        flat.append(m)
                # Filter false positive umum
                flat = [x for x in flat if not is_false_positive(name, x)]
                flat = list(set(flat))[:50]
                if flat:
                    results[name] = flat
        except Exception:
            pass
    return results


def is_false_positive(pattern_name, value):
    """Cek apakah value kemungkinan false positive."""
    value_lower = value.lower() if isinstance(value, str) else ""

    # Filter umum
    blacklist = [
        "example.com", "test.com", "localhost", "admin@admin.com",
        "user@example.com", "email@example.com", "password123",
        "changeme", "your_password", "yourpassword", "password_here",
    ]
    if any(b in value_lower for b in blacklist):
        return True

    # Email: harus ada TLD valid minimal 2 char
    if pattern_name == "email":
        if not re.match(r"^[^@]+@[^@]+\.[a-z]{2,}$", value_lower):
            return True
        # Skip email placeholder
        if any(x in value_lower for x in ["noreply", "no-reply", "donotreply"]):
            return True

    # Password: skip kalo cuma kata umum
    if pattern_name == "password":
        common_words = ["password", "passwd", "pwd", "test", "admin", "user"]
        if value_lower in common_words:
            return True

    # IP: skip private range (double check)
    if pattern_name == "public_ip":
        parts = value.split(".")
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first in (10, 127, 0, 255): return True
                if first == 192 and second == 168: return True
                if first == 172 and 16 <= second <= 31: return True
            except ValueError:
                return True

    return False


def scan_paste(url, rotator):
    # Skip URL ga relevan
    if should_skip_url(url):
        return None

    content = fetch(url, rotator)
    if not content:
        return None

    soup = BeautifulSoup(content, "lxml")

    # Coba textarea dulu (pastebin/rentry format)
    textarea = soup.find("textarea")
    if textarea:
        raw = textarea.get_text()
    else:
        # Ambil dari tag <pre> atau <code> (paste site umumnya di sini)
        pre = soup.find("pre") or soup.find("code")
        if pre:
            raw = pre.get_text()
        else:
            # Fallback: body text, buang script/style
            for tag in soup(["script", "style", "nav", "header", "footer", "aside"]):
                tag.decompose()
            raw = soup.get_text()

    if len(raw) < 100:  # minimal 100 karakter
        return None

    findings = extract_patterns(raw)

    # Filter: minimal 2 pattern BERBEDA biar ga false positive
    if findings and len(findings) >= 2:
        return {"url": url, "size": len(raw), "findings": findings}

    # Atau 1 pattern tapi harus email/hash/wallet (bukan password generic)
    if findings and len(findings) == 1:
        strong_patterns = ["email", "hash_md5", "hash_sha1", "hash_sha256",
                          "credit_card", "btc_wallet", "eth_wallet",
                          "private_key", "aws_key", "db_conn"]
        if any(k in findings for k in strong_patterns):
            return {"url": url, "size": len(raw), "findings": findings}

    return None


def worker(queue, results, rotator, lock, counter):
    while True:
        try:
            url = queue.get_nowait()
        except Exception:
            break
        try:
            res = scan_paste(url, rotator)
            if res:
                with lock:
                    results.append(res)
                    counter["found"] += 1
        except Exception:
            pass
        finally:
            with lock:
                counter["done"] += 1
            queue.task_done()
            time.sleep(random.uniform(0.2, 1))


def run_leak_scan(threads=20):
    """Dipanggil dari bot. Return dict: {results, file, time}"""
    global THREADS
    THREADS = max(1, min(threads, 50))

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    proxies = PROXY_LIST if PROXY_LIST else fetch_free_proxies()
    rotator = ProxyRotator(proxies) if proxies else None

    all_links = []
    for name, url in SOURCES.items():
        links = scrape_links(name, url, rotator)
        all_links.extend(links)
        time.sleep(random.uniform(0.5, 1.5))

    all_links = list(set(all_links))
    if not all_links:
        return {"results": [], "file": None, "time": "0 link"}

    queue = Queue()
    for link in all_links:
        queue.put(link)

    results = []
    lock = threading.Lock()
    counter = {"done": 0, "found": 0}

    threads_list = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(queue, results, rotator, lock, counter))
        t.daemon = True
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join(timeout=60)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(OUTPUT_DIR, f"leak_results_{timestamp}.json")
    if results:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    return {
        "results": results,
        "file": out_file if results else None,
        "time": f"{counter['done']} link diproses, {counter['found']} hit",
    }


def load_leak_results(path=None):
    if path is None:
        if not os.path.isdir(OUTPUT_DIR):
            return None
        files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("leak_results_")])
        if not files:
            return None
        path = os.path.join(OUTPUT_DIR, files[-1])
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
