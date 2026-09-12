import socket
import ssl
import json
import requests
import dns.resolver
import dns.zone
import dns.query
from urllib.parse import urlparse
from modules.utils import resolve_domain

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"}
TIMEOUT = 10


def dns_enum(domain):
    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR"]
    for rtype in types:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in ans]
        except:
            records[rtype] = []
    return records


def zone_transfer(domain):
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        for ns in ns_answers:
            ns_str = str(ns).rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=5))
                if z:
                    return [str(n) for n in z.nodes.keys()]
            except:
                pass
    except:
        pass
    return []


def subdomain_scan(domain, wordlist=None):
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
            "blog", "shop", "store", "cdn", "static", "app", "portal",
            "vpn", "remote", "git", "jenkins", "docker", "k8s", "db",
            "mysql", "postgres", "redis", "mongo", "smtp", "pop", "imap",
            "webmail", "cpanel", "whm", "ns1", "ns2", "dns", "mx",
            "login", "auth", "sso", "oauth", "id", "account", "secure",
            "beta", "alpha", "demo", "sandbox", "internal", "private",
            "old", "new", "backup", "temp", "test2", "dev2", "stg",
            "api2", "v2", "v1", "mobile", "m", "wap", "pda",
            "forum", "community", "support", "help", "docs", "wiki",
            "status", "monitor", "metrics", "grafana", "prometheus",
            "kibana", "elastic", "log", "logs", "trace", "jaeger",
            "argocd", "rancher", "portainer", "traefik", "nginx",
        ]
    found = []
    for sub in wordlist:
        target = f"{sub}.{domain}"
        ip = resolve_domain(target)
        if ip:
            found.append({"subdomain": target, "ip": ip})
    return found


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)
    except:
        return None


def ip_info(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=66846719",
            headers=HEADERS, timeout=TIMEOUT
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "IP": data.get("query"),
                "Country": data.get("country"),
                "Region": data.get("regionName"),
                "City": data.get("city"),
                "ZIP": data.get("zip"),
                "Lat/Lon": f"{data.get('lat')}, {data.get('lon')}",
                "ISP": data.get("isp"),
                "Org": data.get("org"),
                "AS": data.get("as"),
                "Timezone": data.get("timezone"),
                "Proxy/VPN": data.get("proxy"),
                "Hosting": data.get("hosting"),
            }
        return {"error": "IP tidak ditemukan"}
    except Exception as e:
        return {"error": str(e)}


def shodan_lookup(ip, api_key):
    if not api_key:
        return {"error": "Shodan API key tidak ada"}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=TIMEOUT
        )
        data = r.json()
        if "error" in data:
            return {"error": data["error"]}
        return {
            "IP": data.get("ip_str"),
            "Org": data.get("org"),
            "OS": data.get("os"),
            "Ports": data.get("ports", []),
            "Hostnames": data.get("hostnames", []),
            "Country": data.get("country_name"),
            "City": data.get("city"),
            "Vulns": list(data.get("vulns", {}).keys()),
        }
    except Exception as e:
        return {"error": str(e)}


def whois_lookup(domain):
    try:
        r = requests.get(
            f"https://api.hackertarget.com/whois/?q={domain}",
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            return r.text[:3000]
        return {"error": "WHOIS gagal"}
    except Exception as e:
        return {"error": str(e)}


def ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            return {
                "Subject CN": subject.get("commonName"),
                "Subject O": subject.get("organizationName"),
                "Issuer CN": issuer.get("commonName"),
                "Issuer O": issuer.get("organizationName"),
                "Not Before": cert.get("notBefore"),
                "Not After": cert.get("notAfter"),
                "Serial": cert.get("serialNumber"),
                "SAN": cert.get("subjectAltName", [])[:20],
                "Version": cert.get("version"),
            }
    except Exception as e:
        return {"error": str(e)}


def tech_detect(url):
    tech = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        headers = r.headers
        html = r.text[:10000].lower()

        if "server" in headers:
            tech.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech.append(f"Powered-By: {headers['x-powered-by']}")
        if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
            tech.append("Cloudflare CDN")
        if "wp-content" in html or "wordpress" in html:
            tech.append("WordPress")
        if "drupal" in html:
            tech.append("Drupal")
        if "joomla" in html:
            tech.append("Joomla")
        if "react" in html:
            tech.append("React")
        if "vue" in html:
            tech.append("Vue.js")
        if "angular" in html:
            tech.append("Angular")
        if "jquery" in html:
            tech.append("jQuery")
        if "bootstrap" in html:
            tech.append("Bootstrap")
        if "laravel" in headers.get("set-cookie", "").lower():
            tech.append("Laravel")
        if "django" in headers.get("set-cookie", "").lower():
            tech.append("Django")
        if "express" in headers.get("x-powered-by", "").lower():
            tech.append("Express.js")
        if "nginx" in headers.get("server", "").lower():
            tech.append("Nginx")
        if "apache" in headers.get("server", "").lower():
            tech.append("Apache")
        if "iis" in headers.get("server", "").lower():
            tech.append("IIS")
    except:
        pass
    return tech


def waf_detect(url):
    wafs = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
        "AWS WAF": ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
        "Akamai": ["akamai", "ak-bmsc", "x-akamai"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
        "F5 BIG-IP": ["bigipserver", "x-wa-info", "f5"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Fastly": ["x-fastly", "fastly"],
        "Cloudfront": ["x-amz-cf-id", "cloudfront"],
        "Wordfence": ["wordfence"],
    }
    detected = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        headers_str = str(r.headers).lower()
        cookies_str = str(r.cookies).lower()
        body = r.text[:5000].lower()
        for waf, sigs in wafs.items():
            for sig in sigs:
                if sig in headers_str or sig in cookies_str or sig in body:
                    detected.append(waf)
                    break
    except:
        pass
    return detected


def cors_check(url):
    results = []
    try:
        r = requests.get(url, headers={**HEADERS, "Origin": "https://evil.com"},
                         timeout=TIMEOUT, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" or "evil.com" in acao:
            results.append({
                "issue": "CORS Misconfiguration",
                "acao": acao,
                "acac": acac,
                "severity": "HIGH" if acac == "true" else "MEDIUM",
            })
    except:
        pass
    return results


def dork_search(domain):
    dorks = [
        f'site:{domain} ext:php',
        f'site:{domain} ext:sql',
        f'site:{domain} ext:env',
        f'site:{domain} ext:bak',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:api',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:backup',
        f'site:{domain} "password"',
        f'site:{domain} "api_key"',
        f'site:{domain} "secret"',
        f'site:{domain} "token"',
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls',
        f'site:{domain} filetype:doc',
        f'site:{domain} inurl:phpinfo',
        f'site:{domain} inurl:wp-content',
        f'site:{domain} inurl:wp-config',
    ]
    return dorks
