#!/usr/bin/env python3
# modules/leak_agg.py
# Leak Aggregator - rotasi proxy + multithread
# Requirements: pip install requests beautifulsoup4 lxml fake-useragent

import os
import re
import json
import time
import random
import threading
from queue import Queue
from urllib.parse import urljoin
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


PATTERNS = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "password": r"(?i)(password|passwd|pwd|pass)[\s:=]+([^\s]{4,})",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha1": r"\b[a-fA-F0-9]{40}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "btc_wallet": r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
    "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "api_key": r"(?i)(api[_-]?key|apikey|secret)[\s:=]+([a-zA-Z0-9_\-]{16,})",
}

SOURCES = {
    "pastebin_archive": "https://pastebin.com/archive",
    "pastebin_trending": "https://pastebin.com/trends",
    "rentry": "https://rentry.co/",
    "ghostbin": "https://ghostbin.com/",
    "dpaste": "https://dpaste.com/",
    "hastebin": "https://hastebin.com/",
    "controlc": "https://controlc.com/",
}


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
    return list(set(links))[:100]


def extract_patterns(text):
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
                flat = list(set(flat))[:50]
                if flat:
                    results[name] = flat
        except Exception:
            pass
    return results


def scan_paste(url, rotator):
    content = fetch(url, rotator)
    if not content:
        return None
    soup = BeautifulSoup(content, "lxml")
    textarea = soup.find("textarea")
    if textarea:
        raw = textarea.get_text()
    else:
        for tag in soup(["script", "style", "nav", "header", "footer"]):
            tag.decompose()
        raw = soup.get_text()
    if len(raw) < 50:
        return None
    findings = extract_patterns(raw)
    if findings:
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
        "time": f"{counter['done']} link diproses",
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
