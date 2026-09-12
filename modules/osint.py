import re
import os
import socket
import requests
import json
import math
from urllib.parse import quote

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 15


# ================== EMAIL ==================

def email_check(email):
    result = {"email": email}
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return {"error": "Format email tidak valid"}
    username, domain = email.split("@")
    result["username"] = username
    result["domain"] = domain
    providers = {
        "gmail.com": "Google Gmail", "yahoo.com": "Yahoo Mail",
        "outlook.com": "Microsoft Outlook", "hotmail.com": "Microsoft Hotmail",
        "protonmail.com": "ProtonMail", "icloud.com": "Apple iCloud",
        "mail.com": "Mail.com", "yandex.com": "Yandex Mail", "zoho.com": "Zoho Mail",
    }
    result["provider"] = providers.get(domain.lower(), "Unknown / Custom domain")
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx]
        result["valid_domain"] = True
    except:
        result["mx_records"] = []
        result["valid_domain"] = False
    try:
        import hashlib
        h = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        r = requests.head(url, timeout=TIMEOUT)
        result["gravatar"] = r.status_code == 200
    except:
        result["gravatar"] = None
    return result


# ================== PHONE ==================

def phone_check(number, region="ID", use_api=True):
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
        parsed = phonenumbers.parse(number, region)
        if not phonenumbers.is_valid_number(parsed):
            return {"error": "Nomor tidak valid"}
        line_types = {0: "Unknown", 1: "Fixed Line", 2: "Mobile",
                      3: "Fixed Line or Mobile", 4: "Toll Free",
                      5: "Premium Rate", 6: "Shared Cost", 7: "VoIP",
                      8: "Personal Number", 9: "Pager", 10: "UAN", 11: "Voicemail"}
        return {
            "source": "phonenumbers (offline)",
            "number": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "local_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_prefix": f"+{parsed.country_code}",
            "country_code": phonenumbers.region_code_for_number(parsed),
            "country_name": geocoder.description_for_number(parsed, "id") or "Unknown",
            "location": geocoder.description_for_number(parsed, "id") or "Unknown",
            "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
            "line_type": line_types.get(phonenumbers.number_type(parsed), "Unknown"),
            "timezone": ", ".join(timezone.time_zones_for_number(parsed)) or "Unknown",
        }
    except Exception as e:
        return {"error": str(e)}


# ================== USERNAME ==================

def username_check(username):
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "Twitter/X": f"https://twitter.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Telegram": f"https://t.me/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Gitlab": f"https://gitlab.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Linktree": f"https://linktr.ee/{username}",
        "VK": f"https://vk.com/{username}",
    }
    found, not_found = [], []
    for name, url in platforms.items():
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200:
                tl = r.text.lower()
                nf = ["page not found", "user not found", "doesn't exist",
                      "sorry, this page", "couldn't find", "not available",
                      "404", "no user", "profile not found"]
                if not any(k in tl for k in nf):
                    found.append({"platform": name, "url": url})
                else:
                    not_found.append(name)
            else:
                not_found.append(name)
        except:
            not_found.append(name)
    return {"username": username, "found": found, "not_found": not_found,
            "total_found": len(found), "total_checked": len(platforms)}


# ================== GITHUB ==================

def github_check(username):
    try:
        r = requests.get(f"https://api.github.com/users/{username}",
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"error": "User GitHub tidak ditemukan"}
        if r.status_code != 200:
            return {"error": f"GitHub API error: {r.status_code}"}
        data = r.json()
        repos = []
        try:
            r2 = requests.get(
                f"https://api.github.com/users/{username}/repos?per_page=10&sort=updated",
                headers=HEADERS, timeout=TIMEOUT)
            if r2.status_code == 200:
                for repo in r2.json():
                    repos.append({
                        "name": repo["name"], "url": repo["html_url"],
                        "stars": repo["stargazers_count"],
                        "lang": repo.get("language", "N/A"),
                    })
        except:
            pass
        return {"username": data.get("login"), "name": data.get("name"),
                "bio": data.get("bio"), "company": data.get("company"),
                "location": data.get("location"), "email": data.get("email"),
                "blog": data.get("blog"), "twitter": data.get("twitter_username"),
                "public_repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "following": data.get("following"),
                "created_at": data.get("created_at"),
                "avatar": data.get("avatar_url"), "repos": repos}
    except Exception as e:
        return {"error": str(e)}


# ================== TELEGRAM ==================

def telegram_check(username):
    username = username.lstrip("@")
    try:
        r = requests.get(f"https://t.me/{username}", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"exists": False, "username": username}
        text = r.text
        if "tgme_page_title" in text:
            tm = re.search(r'<meta property="og:title" content="([^"]+)"', text)
            dm = re.search(r'<meta property="og:description" content="([^"]+)"', text)
            im = re.search(r'<meta property="og:image" content="([^"]+)"', text)
            return {"exists": True, "username": username,
                    "title": tm.group(1) if tm else "N/A",
                    "description": dm.group(1) if dm else "N/A",
                    "url": f"https://t.me/{username}",
                    "has_photo": bool(im)}
        return {"exists": False, "username": username}
    except Exception as e:
        return {"error": str(e)}


# ================== DOMAIN ==================

def domain_info(domain):
    result = {"domain": domain}
    try:
        result["ip"] = socket.gethostbyname(domain)
    except:
        result["ip"] = None
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain}",
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text.lower():
            result["whois"] = r.text[:2000]
    except:
        pass
    try:
        import dns.resolver
        records = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                ans = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in ans]
            except:
                records[rtype] = []
        result["dns"] = records
    except:
        pass
    return result


# ================== IP ==================

def ip_full_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=TIMEOUT)
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "IP tidak ditemukan")}
        return {"ip": data.get("query"), "country": data.get("country"),
                "country_code": data.get("countryCode"), "region": data.get("regionName"),
                "city": data.get("city"), "zip": data.get("zip"),
                "lat": data.get("lat"), "lon": data.get("lon"),
                "timezone": data.get("timezone"), "isp": data.get("isp"),
                "org": data.get("org"), "as": data.get("as"),
                "asname": data.get("asname"), "reverse": data.get("reverse"),
                "mobile": data.get("mobile"), "proxy": data.get("proxy"),
                "hosting": data.get("hosting")}
    except Exception as e:
        return {"error": str(e)}


# ================== MX ==================

def mx_lookup(domain):
    result = {"domain": domain}
    try:
        import dns.resolver
        try:
            mx = dns.resolver.resolve(domain, "MX", lifetime=5)
            result["mx"] = [f"{r.preference} {r.exchange}" for r in mx]
        except:
            result["mx"] = []
        try:
            txt = dns.resolver.resolve(domain, "TXT", lifetime=5)
            result["spf"] = [str(r).strip('"') for r in txt if "v=spf1" in str(r)]
        except:
            result["spf"] = []
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            result["dmarc"] = [str(r).strip('"') for r in dmarc]
        except:
            result["dmarc"] = []
        return result
    except Exception as e:
        return {"error": str(e)}


# ================== SUBDOMAIN ==================

def subdomain_crtsh(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return {"error": f"crt.sh error: {r.status_code}"}
        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for s in name.split("\n"):
                s = s.strip().lower()
                if s and "*" not in s and s.endswith(domain):
                    subs.add(s)
        return {"domain": domain, "total": len(subs), "subdomains": sorted(subs)}
    except Exception as e:
        return {"error": str(e)}


# ================== ROBOTS ==================

def robots_check(domain):
    result = {"domain": domain}
    try:
        r = requests.get(f"https://{domain}/robots.txt", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            result["robots"] = r.text[:2000]
            sitemaps = re.findall(r"Sitemap:\s*(.+)", r.text, re.IGNORECASE)
            result["sitemaps"] = [s.strip() for s in sitemaps]
        else:
            result["robots"] = None
    except:
        result["robots"] = None
    return result


# ================== HEADERS ==================

def headers_check(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        headers = r.headers
        sh = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
            "Server": headers.get("Server"),
            "X-Powered-By": headers.get("X-Powered-By"),
        }
        present = [k for k, v in sh.items() if v]
        missing = [k for k, v in sh.items() if not v]
        return {"url": url, "status": r.status_code, "headers": sh,
                "present": present, "missing": missing}
    except Exception as e:
        return {"error": str(e)}


# ================== MY IP ==================

def my_ip():
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


# ================== GEOLOCATION ==================

def geoloc_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=TIMEOUT)
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "IP tidak ditemukan")}
        lat = data.get("lat")
        lon = data.get("lon")
        return {"ip": data.get("query"), "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"), "city": data.get("city"),
                "zip": data.get("zip"), "lat": lat, "lon": lon,
                "timezone": data.get("timezone"), "isp": data.get("isp"),
                "org": data.get("org"), "as": data.get("as"),
                "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"}
    except Exception as e:
        return {"error": str(e)}


def geocode_search(query):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search",
                         params={"q": query, "format": "json", "limit": 5, "addressdetails": 1},
                         headers={"User-Agent": "DiabloXHunt/1.0"}, timeout=TIMEOUT)
        data = r.json()
        if not data:
            return {"error": "Lokasi tidak ditemukan"}
        results = []
        for item in data[:5]:
            lat = float(item.get("lat"))
            lon = float(item.get("lon"))
            results.append({
                "display_name": item.get("display_name"),
                "lat": lat, "lon": lon,
                "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"})
        return {"query": query, "results": results}
    except Exception as e:
        return {"error": str(e)}


def reverse_geocode(lat, lon):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"lat": lat, "lon": lon, "format": "json",
                                 "addressdetails": 1, "zoom": 18},
                         headers={"User-Agent": "DiabloXHunt/1.0"}, timeout=TIMEOUT)
        data = r.json()
        if data.get("error"):
            return {"error": data["error"]}
        addr = data.get("address", {})
        return {"lat": lat, "lon": lon,
                "display_name": data.get("display_name"),
                "road": addr.get("road"), "village": addr.get("village"),
                "suburb": addr.get("suburb"),
                "city": addr.get("city") or addr.get("town"),
                "state": addr.get("state"), "postcode": addr.get("postcode"),
                "country": addr.get("country"),
                "maps_url": f"https://www.google.com/maps?q={lat},{lon}"}
    except Exception as e:
        return {"error": str(e)}


def distance_calc(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    d = R * c
    return {"from": {"lat": lat1, "lon": lon1}, "to": {"lat": lat2, "lon": lon2},
            "distance_km": round(d, 2), "distance_miles": round(d * 0.621371, 2),
            "maps_url": f"https://www.google.com/maps/dir/{lat1},{lon1}/{lat2},{lon2}"}
