import re
import socket
import hashlib
import base64
import time


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None


def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(x) <= 255 for x in ip.split("."))


def resolve_domain(domain: str):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def normalize_url(target: str) -> str:
    target = target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def hash_string(s: str, algo="md5"):
    h = hashlib.new(algo)
    h.update(s.encode())
    return h.hexdigest()


def base64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def base64_decode(s: str) -> str:
    return base64.b64decode(s.encode()).decode()


def get_severity_color(sev):
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")


def load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except:
        return []


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")
