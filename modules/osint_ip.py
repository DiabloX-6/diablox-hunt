import requests

def scan_ip(ip: str) -> str:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=66846719",
            timeout=10
        )
        d = r.json()
        if d.get("status") == "fail":
            return f"❌ Gagal: {d.get('message')}"
        keys = ["query", "country", "countryCode", "regionName", "city",
                "zip", "lat", "lon", "timezone", "isp", "org", "as", "mobile", "proxy", "hosting"]
        return "\n".join(f"`{k}`: *{d.get(k, '-')}*" for k in keys)
    except Exception as e:
        return f"❌ Error: {e}"
