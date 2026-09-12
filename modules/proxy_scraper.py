import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor

SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
]

PROXY_REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
TEST_URL = "http://httpbin.org/ip"
FETCH_TIMEOUT = 8
TEST_TIMEOUT = 4
MAX_WORKERS = 150


def log(msg):
    print(f"[PROXY] {msg}", flush=True)


def fetch_source(url):
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return []
        proxies = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if PROXY_REGEX.match(line):
                proxies.append(line)
        return proxies
    except Exception as e:
        log(f"Gagal fetch {url[:60]}... : {e}")
        return []


def test_proxy(proxy, timeout=TEST_TIMEOUT):
    try:
        r = requests.get(
            TEST_URL,
            proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200 and "origin" in r.text:
            return (proxy, True)
    except Exception:
        pass
    return (proxy, False)


def scrape_all_proxies(progress_cb=None):
    log("Mulai scrape proxy...")
    all_proxies = set()
    for i, url in enumerate(SOURCES, 1):
        if progress_cb:
            try:
                progress_cb("fetch", i, len(SOURCES))
            except:
                pass
        batch = fetch_source(url)
        log(f"Sumber {i}/{len(SOURCES)}: {len(batch)} proxy")
        all_proxies.update(batch)

    log(f"Total proxy unik mentah: {len(all_proxies)}")
    if not all_proxies:
        return []

    log(f"Health check {len(all_proxies)} proxy...")
    alive = []
    total = len(all_proxies)
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for proxy, ok in ex.map(test_proxy, all_proxies):
            done += 1
            if progress_cb and done % 100 == 0:
                try:
                    progress_cb("check", done, total)
                except:
                    pass
            if ok:
                alive.append(proxy)

    log(f"Selesai. Proxy hidup: {len(alive)}/{total}")
    return alive


def save_to_file(proxies, path="proxy.txt"):
    with open(path, "w") as f:
        f.write("# Auto-scraped proxies\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total: {len(proxies)}\n\n")
        for p in proxies:
            f.write(p + "\n")
    log(f"Saved {len(proxies)} proxies → {path}")


def refresh_proxy_file(path="proxy.txt"):
    proxies = scrape_all_proxies()
    if proxies:
        save_to_file(proxies, path)
    else:
        log("Tidak ada proxy hidup, file tidak ditimpa")
    return len(proxies)


if __name__ == "__main__":
    n = refresh_proxy_file()
    print(f"\n=== SELESAI ===\nTotal proxy hidup: {n}\nFile: proxy.txt")
