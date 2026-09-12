import os
import json
import logging
import asyncio
import base64
from datetime import datetime
from urllib.parse import urlparse

from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, ContextTypes
)

from modules.utils import (
    is_valid_domain, resolve_domain, normalize_url,
    get_severity_color, base64_encode, base64_decode, hash_string,
)
from modules.recon import (
    dns_enum, zone_transfer, subdomain_scan, reverse_dns,
    ip_info, shodan_lookup, whois_lookup, ssl_info,
    tech_detect, waf_detect, cors_check, dork_search,
)
from modules.vuln import VulnScanner
from modules.report import save_json_report, save_html_report

# ================== KONFIGURASI ==================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
OWNER = os.getenv("OWNER", "Naddd")
BOT_NAME = os.getenv("BOT_NAME", "DiabloX Hunt")
VERSION = "1.0"
# =================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def get_arg(context) -> str:
    return context.args[0] if context.args else ""


def fmt_findings(findings, limit=15) -> str:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 5))
    text = ""
    for f in findings[:limit]:
        e = get_severity_color(f["severity"])
        name = f["name"].replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
        url = f["url"].replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
        text += f"{e} *{name}*\n   `{url[:80]}`\n"
        if f.get("evidence"):
            ev = f["evidence"].replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
            text += f"   _{ev[:120]}_\n"
        text += "\n"
    if len(findings) > limit:
        text += f"_... dan {len(findings)-limit} temuan lainnya_\n"
    return text


def summary_text(findings) -> str:
    sev_count = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
    text = "*Ringkasan:*\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_count:
            text += f"{get_severity_color(sev)} {sev}: {sev_count[sev]}\n"
    return text


# ================== INFO ==================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        f"🛡️ *{DiabloXhunt}* — PUBLIC\n"
        f"👤 Owner: *{Naddd}*\n\n"
        "*RECON:*\n"
        "/dns `<domain>` — DNS enum\n"
        "/sub `<domain>` — Subdomain scan\n"
        "/whois `<domain>` — WHOIS\n"
        "/ip `<ip/domain>` — IP info\n"
        "/ssl `<domain>` — SSL cert\n"
        "/tech `<url>` — Tech detect\n"
        "/waf `<url>` — WAF detect\n"
        "/shodan `<ip>` — Shodan\n"
        "/dork `<domain>` — Google dork\n"
        "/axfr `<domain>` — Zone transfer\n"
        "/rev `<ip>` — Reverse DNS\n\n"
        "*VULN:*\n"
        "/scan `<domain>` — Full scan\n"
        "/sqli `<url>` — SQL injection\n"
        "/xss `<url>` — XSS\n"
        "/lfi `<url>` — LFI\n"
        "/ssrf `<url>` — SSRF\n"
        "/redirect `<url>` — Open redirect\n"
        "/cors `<url>` — CORS\n"
        "/methods `<url>` — HTTP methods\n"
        "/dir `<url>` — Dir bruteforce\n\n"
        "*TOOLS:*\n"
        "/base64e `<text>` — Encode\n"
        "/base64d `<text>` — Decode\n"
        "/hash `<text>` — Hash\n"
        "/jwt `<token>` — Decode JWT\n\n"
        "*INFO:*\n"
        "/owner — Owner bot\n"
        "/info — Info bot\n"
        "/help — Bantuan\n\n"
        "⚠️ _Gunakan hanya untuk domain milik Anda._"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        f"📖 *CARA PAKAI {DiabloXhunt}*\n"
        f"👤 Owner: *{Naddd}*\n\n"
        "Kirim perintah dengan argumen.\n"
        "Bot proses 1-3 menit.\n\n"
        "*Contoh:*\n"
        "`/scan example.com`\n"
        "`/sub example.com`\n"
        "`/dns example.com`\n"
        "`/ip 8.8.8.8`\n"
        "`/hash hello`\n\n"
        "⚠️ *Gunakan hanya untuk domain milik Anda.*"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def owner_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "==========================\n"
        "========= OWNER ==========\n"
        "==========================\n"
        f"#  Nama: {Naddd}                     #\n"
        "=========================="
    )
    await update.message.reply_text(f"```\n{text}\n```", parse_mode="Markdown")


async def info_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        f"====== INFO {BOT_NAME.upper()} ======\n"
        f"Bot    : {BOT_NAME}\n"
        f"Versi  : {VERSION}\n"
        f"Owner  : {OWNER}\n"
        f"Status : PUBLIC\n"
        "==========================\n"
        "Bot scanner kerentanan website\n"
        "untuk edukasi & authorized pentest.\n"
        f"Dibuat oleh {Naddd}.\n"
        "=========================="
    )
    await update.message.reply_text(f"```\n{text}\n```", parse_mode="Markdown")


# ================== RECON ==================

async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain or not is_valid_domain(domain):
        await update.message.reply_text("❌ Format: `/dns example.com`", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"🔍 DNS enum `{domain}`...", parse_mode="Markdown")
    try:
        records = await asyncio.to_thread(dns_enum, domain)
        text = f"🌐 *DNS: {domain}*\n\n"
        for rtype, values in records.items():
            if values:
                text += f"*{rtype}:*\n"
                for v in values[:5]:
                    text += f"  `{v}`\n"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def sub_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain or not is_valid_domain(domain):
        await update.message.reply_text("❌ Format: `/sub example.com`", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"🔍 Subdomain scan `{domain}`...", parse_mode="Markdown")
    try:
        subs = await asyncio.to_thread(subdomain_scan, domain)
        if not subs:
            await msg.edit_text("❌ Tidak ada subdomain ditemukan")
            return
        text = f"🌐 *Subdomains: {domain}* ({len(subs)})\n\n"
        for s in subs[:40]:
            text += f"• `{s['subdomain']}` → `{s['ip']}`\n"
        if len(subs) > 40:
            text += f"\n_... dan {len(subs)-40} lainnya_"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def whois_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain:
        await update.message.reply_text("❌ Format: `/whois example.com`", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"🔍 WHOIS `{domain}`...", parse_mode="Markdown")
    try:
        result = await asyncio.to_thread(whois_lookup, domain)
        if isinstance(result, dict) and "error" in result:
            await msg.edit_text(f"❌ {result['error']}")
            return
        await msg.edit_text(f"📋 *WHOIS: {domain}*\n\n`{result[:3500]}`", parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def ip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = get_arg(context)
    if not target:
        await update.message.reply_text("❌ Format: `/ip 8.8.8.8`", parse_mode="Markdown")
        return
    try:
        ip = target if target.replace(".", "").isdigit() else await asyncio.to_thread(resolve_domain, target)
        if not ip:
            await update.message.reply_text(f"❌ Tidak bisa resolve `{target}`")
            return
        msg = await update.message.reply_text(f"🔍 IP info `{ip}`...", parse_mode="Markdown")
        info = await asyncio.to_thread(ip_info, ip)
        if "error" in info:
            await msg.edit_text(f"❌ {info['error']}")
            return
        text = f"🌍 *IP Info: {info['IP']}*\n\n"
        for k, v in info.items():
            if k != "IP":
                text += f"*{k}:* `{v}`\n"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


async def ssl_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain:
        await update.message.reply_text("❌ Format: `/ssl example.com`", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"🔍 SSL check `{domain}`...", parse_mode="Markdown")
    try:
        info = await asyncio.to_thread(ssl_info, domain)
        if "error" in info:
            await msg.edit_text(f"❌ {info['error']}")
            return
        text = f"🔒 *SSL: {domain}*\n\n"
        for k, v in info.items():
            text += f"*{k}:* `{v}`\n"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def tech_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = get_arg(context)
    if not url:
        await update.message.reply_text("❌ Format: `/tech https://example.com`", parse_mode="Markdown")
        return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Tech detect `{url}`...", parse_mode="Markdown")
    try:
        tech = await asyncio.to_thread(tech_detect, url)
        text = f"🔧 *Technologies: {url}*\n\n"
        if tech:
            for t in tech:
                text += f"• `{t}`\n"
        else:
            text += "_Tidak terdeteksi_"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def waf_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = get_arg(context)
    if not url:
        await update.message.reply_text("❌ Format: `/waf https://example.com`", parse_mode="Markdown")
        return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 WAF detect `{url}`...", parse_mode="Markdown")
    try:
        wafs = await asyncio.to_thread(waf_detect, url)
        text = f"🛡️ *WAF: {url}*\n\n"
        if wafs:
            for w in wafs:
                text += f"• `{w}`\n"
        else:
            text += "_Tidak terdeteksi WAF_"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def shodan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = get_arg(context)
    if not ip:
        await update.message.reply_text("❌ Format: `/shodan 8.8.8.8`", parse_mode="Markdown")
        return
    if not SHODAN_KEY:
        await update.message.reply_text("❌ Shodan API key belum di-set")
        return
    msg = await update.message.reply_text(f"🔍 Shodan `{ip}`...", parse_mode="Markdown")
    try:
        info = await asyncio.to_thread(shodan_lookup, ip, SHODAN_KEY)
        if "error" in info:
            await msg.edit_text(f"❌ {info['error']}")
            return
        text = f"🔎 *Shodan: {info['IP']}*\n\n"
        text += f"*Org:* `{info.get('Org')}`\n"
        text += f"*OS:* `{info.get('OS')}`\n"
        text += f"*Ports:* `{info.get('Ports')}`\n"
        if info.get("Vulns"):
            text += f"*Vulns:* `{info['Vulns']}`\n"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def dork_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain:
        await update.message.reply_text("❌ Format: `/dork example.com`", parse_mode="Markdown")
        return
    dorks = dork_search(domain)
    text = f"🔍 *Google Dorks: {domain}*\n\n"
    for d in dorks:
        text += f"`{d}`\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def axfr_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = get_arg(context)
    if not domain:
        await update.message.reply_text("❌ Format: `/axfr example.com`", parse_mode="Markdown")
        return
    msg = await update.message.reply_text(f"🔍 Zone transfer `{domain}`...", parse_mode="Markdown")
    try:
        records = await asyncio.to_thread(zone_transfer, domain)
        if records:
            text = "⚠️ *ZONE TRANSFER BERHASIL!*\n\n"
            for r in records[:50]:
                text += f"`{r}`\n"
            await msg.edit_text(text, parse_mode="Markdown")
        else:
            await msg.edit_text("✅ Zone transfer gagal (dilindungi)")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def rev_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = get_arg(context)
    if not ip:
        await update.message.reply_text("❌ Format: `/rev 8.8.8.8`", parse_mode="Markdown")
        return
    try:
        result = await asyncio.to_thread(reverse_dns, ip)
        if result:
            await update.message.reply_text(f"🔍 *Reverse DNS {ip}:*\n\n`{result}`", parse_mode="Markdown")
        else:
            await update.message.reply_text(f"❌ Tidak ada PTR record untuk `{ip}`")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


# ================== VULN ==================

async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = get_arg(context)
    if not target:
        await update.message.reply_text("❌ Format: `/scan example.com`", parse_mode="Markdown")
        return
    url = normalize_url(target)
    domain = urlparse(url).hostname
    if not is_valid_domain(domain):
        await update.message.reply_text("❌ Domain tidak valid")
        return
    if not resolve_domain(domain):
        await update.message.reply_text("❌ Domain tidak bisa di-resolve")
        return

    msg = await update.message.reply_text(
        f"🔍 *Full scan* `{domain}`...\n\n⏳ 1-3 menit.", parse_mode="Markdown"
    )

    try:
        scanner = VulnScanner(target)
        result = await asyncio.to_thread(scanner.run)
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")
        return

    if "error" in result:
        await msg.edit_text(f"❌ {result['error']}")
        return

    findings = result["findings"]
    text = f"✅ *SCAN SELESAI*\n\n"
    text += f"🌐 `{result['domain']}`\n"
    text += f"📡 `{result['ip']}`\n"
    text += f"⏰ `{result['time']}`\n\n"
    if findings:
        text += summary_text(findings) + "\n"
        text += fmt_findings(findings, 10)
    else:
        text += "✅ _Tidak ada kerentanan ditemukan_\n"
    if len(text) > 4000:
        text = text[:4000] + "\n\n... (lihat file report)"

    await msg.edit_text(text, parse_mode="Markdown")

    try:
        json_file = save_json_report(result)
        html_file = save_html_report(result)
        with open(json_file, "rb") as f:
            await update.message.reply_document(
                document=f, filename=os.path.basename(json_file),
                caption=f"📄 JSON Report - {result['domain']}"
            )
        with open(html_file, "rb") as f:
            await update.message.reply_document(
                document=f, filename=os.path.basename(html_file),
                caption=f"🌐 HTML Report - {result['domain']}"
            )
    except Exception as e:
        logger.error(f"Report error: {e}")


async def _quick_vuln(update, context, test_name, test_func):
    url = get_arg(context)
    if not url:
        await update.message.reply_text(f"❌ Format: `/{test_name} <url>`", parse_mode="Markdown")
        return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Test {test_name} `{url}`...", parse_mode="Markdown")
    try:
        scanner = VulnScanner(url)
        await asyncio.to_thread(scanner.crawl, url, 1)
        if not scanner.params:
            await msg.edit_text("❌ Tidak ada parameter ditemukan")
            return
        await asyncio.to_thread(test_func, scanner)
        if not scanner.findings:
            await msg.edit_text(f"✅ Tidak ada {test_name} ditemukan")
            return
        text = f"⚠️ *{test_name.upper()} DITEMUKAN!*\n\n"
        text += fmt_findings(scanner.findings, 10)
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


async def sqli_cmd(update, context):
    await _quick_vuln(update, context, "sqli", lambda s: s.test_sqli())

async def xss_cmd(update, context):
    await _quick_vuln(update, context, "xss", lambda s: s.test_xss())

async def lfi_cmd(update, context):
    await _quick_vuln(update, context, "lfi", lambda s: s.test_lfi())

async def ssrf_cmd(update, context):
    await _quick_vuln(update, context, "ssrf", lambda s: s.test_ssrf())

async def redirect_cmd(update, context):
    await _quick_vuln(update, context, "open redirect", lambda s: s.test_open_redirect())

async def methods_cmd(update, context):
    await _quick_vuln(update, context, "http methods", lambda s: s.test_http_methods())


async def cors_cmd(update, context):
    url = get_arg(context)
    if not url:
        await update.message.reply_text("❌ Format: `/cors <url>`", parse_mode="Markdown")
        return
    url = normalize_url(url)
    try:
        results = await asyncio.to_thread(cors_check, url)
        if not results:
            await update.message.reply_text("✅ Tidak ada misconfig CORS")
            return
        text = "⚠️ *CORS Misconfig!*\n\n"
        for r in results:
            text += f"• Severity: `{r['severity']}`\n• ACAO: `{r['acao']}`\n"
        await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


async def dir_cmd(update, context):
    url = get_arg(context)
    if not url:
        await update.message.reply_text("❌ Format: `/dir <url>`", parse_mode="Markdown")
        return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Dir bruteforce `{url}`...", parse_mode="Markdown")
    try:
        scanner = VulnScanner(url)
        await asyncio.to_thread(scanner.dir_bruteforce)
        if not scanner.findings:
            await msg.edit_text("✅ Tidak ada directory ditemukan")
            return
        text = "📁 *Directories Found:*\n\n" + fmt_findings(scanner.findings, 30)
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")


# ================== TOOLS ==================

async def base64e_cmd(update, context):
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("❌ Format: `/base64e hello`", parse_mode="Markdown")
        return
    await update.message.reply_text(f"```\n{base64_encode(text)}\n```", parse_mode="Markdown")


async def base64d_cmd(update, context):
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("❌ Format: `/base64d aGVsbG8=`", parse_mode="Markdown")
        return
    try:
        await update.message.reply_text(f"```\n{base64_decode(text)}\n```", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


async def hash_cmd(update, context):
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("❌ Format: `/hash hello`", parse_mode="Markdown")
        return
    msg = f"*Hashes:* `{text}`\n\n"
    msg += f"*MD5:*\n`{hash_string(text, 'md5')}`\n\n"
    msg += f"*SHA1:*\n`{hash_string(text, 'sha1')}`\n\n"
    msg += f"*SHA256:*\n`{hash_string(text, 'sha256')}`"
    await update.message.reply_text(msg, parse_mode="Markdown")


async def jwt_cmd(update, context):
    token = get_arg(context)
    if not token:
        await update.message.reply_text("❌ Format: `/jwt <token>`", parse_mode="Markdown")
        return
    parts = token.split(".")
    if len(parts) != 3:
        await update.message.reply_text("❌ Bukan JWT valid")
        return
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4)))
        text = f"*JWT Decoded*\n\n*Header:*\n```\n{json.dumps(header, indent=2)}\n```\n"
        text += f"\n*Payload:*\n```\n{json.dumps(payload, indent=2)}\n```"
        await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


# ================== HANDLER ==================

async def handle_text(update, context):
    text = update.message.text.strip()
    if "." in text and " " not in text:
        context.args = [text]
        await scan_cmd(update, context)
    else:
        await update.message.reply_text(f"❌ Ketik /start untuk menu {BOT_NAME}.")


async def error_handler(update, context):
    logger.error(f"Error: {context.error}")


# ================== MAIN ==================

def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN belum di-set di environment")
        return
    app = Application.builder().token(BOT_TOKEN).build()

    # Info
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("owner", owner_cmd))
    app.add_handler(CommandHandler("info", info_cmd))

    # Recon
    app.add_handler(CommandHandler("dns", dns_cmd))
    app.add_handler(CommandHandler("sub", sub_cmd))
    app.add_handler(CommandHandler("whois", whois_cmd))
    app.add_handler(CommandHandler("ip", ip_cmd))
    app.add_handler(CommandHandler("ssl", ssl_cmd))
    app.add_handler(CommandHandler("tech", tech_cmd))
    app.add_handler(CommandHandler("waf", waf_cmd))
    app.add_handler(CommandHandler("shodan", shodan_cmd))
    app.add_handler(CommandHandler("dork", dork_cmd))
    app.add_handler(CommandHandler("axfr", axfr_cmd))
    app.add_handler(CommandHandler("rev", rev_cmd))

    # Vuln
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(CommandHandler("sqli", sqli_cmd))
    app.add_handler(CommandHandler("xss", xss_cmd))
    app.add_handler(CommandHandler("lfi", lfi_cmd))
    app.add_handler(CommandHandler("ssrf", ssrf_cmd))
    app.add_handler(CommandHandler("redirect", redirect_cmd))
    app.add_handler(CommandHandler("cors", cors_cmd))
    app.add_handler(CommandHandler("methods", methods_cmd))
    app.add_handler(CommandHandler("dir", dir_cmd))

    # Tools
    app.add_handler(CommandHandler("base64e", base64e_cmd))
    app.add_handler(CommandHandler("base64d", base64d_cmd))
    app.add_handler(CommandHandler("hash", hash_cmd))
    app.add_handler(CommandHandler("jwt", jwt_cmd))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    print("🛡️ DiabloXhunt running...")
    print(f"👤 Owner: {Naddd}")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
