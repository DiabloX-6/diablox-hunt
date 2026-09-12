import os
import json
import logging
import asyncio
import base64
from datetime import datetime
from urllib.parse import urlparse

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    filters, ContextTypes
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
from database import (
    is_owner, is_registered, is_active, get_user, add_user, remove_user,
    extend_user, ban_user, unban_user, list_users, sisa_hari,
    get_paket_list, set_owner_id, get_owner_id, user_count,
)

# ================== KONFIGURASI ==================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
NAMA_BOT = "DiabloXhunt"
NAMA_OWNER = "Naddd"
VERSION = "2.0"
# =================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ================== CEK AKSES ==================

def cek_akses(uid):
    """Return (status, pesan)"""
    if is_owner(uid):
        return "owner", ""
    if not is_registered(uid):
        return "unregistered", (
            "🔒 *AKSES DITOLAK*\n\n"
            "Kamu belum terdaftar sebagai user.\n\n"
            "Untuk berlangganan, hubungi owner:\n"
            f"Owner: *{NAMA_OWNER}*\n\n"
            "Ketik /paket untuk lihat daftar paket."
        )
    if not is_active(uid):
        user = get_user(uid)
        if user and user.get("status") == "banned":
            return "banned", "🚫 *AKUN DIBANNED*\n\nHubungi owner untuk info lebih lanjut."
        return "expired", (
            "⏰ *LANGGANAN HABIS*\n\n"
            f"Langganan kamu sudah expired.\n"
            "Hubungi owner untuk perpanjang:\n"
            f"Owner: *{NAMA_OWNER}*\n\n"
            "Ketik /paket untuk lihat daftar paket."
        )
    return "active", ""


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


# ================== START & INFO ==================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)

    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return

    if status == "owner":
        text = (
            f"👑 *{NAMA_BOT} — OWNER MODE*\n"
            f"👤 Owner: *{NAMA_OWNER}*\n\n"
            f"📊 Total user: `{user_count()}`\n\n"
            "*OWNER COMMANDS:*\n"
            "/adduser `<id> <nama> <paket>` — Tambah user\n"
            "/removeuser `<id>` — Hapus user\n"
            "/extend `<id> <hari>` — Perpanjang\n"
            "/ban `<id>` — Ban user\n"
            "/unban `<id>` — Unban user\n"
            "/listuser — Lihat semua user\n"
            "/userinfo `<id>` — Info user\n"
            "/setowner `<id>` — Set owner\n\n"
            "*RECON:*\n"
            "/dns `/sub` `/whois` `/ip` `/ssl` `/tech` `/waf` `/shodan` `/dork` `/axfr` `/rev`\n\n"
            "*VULN:*\n"
            "/scan `/sqli` `/xss` `/lfi` `/ssrf` `/redirect` `/cors` `/methods` `/dir`\n\n"
            "*TOOLS:*\n"
            "/base64e `/base64d` `/hash` `/jwt`"
        )
        await update.message.reply_text(text, parse_mode="Markdown")
        return

    user = get_user(uid)
    hari = sisa_hari(uid)
    text = (
        f"🛡️ *{NAMA_BOT}*\n"
        f"👤 Halo, *{user['nama']}*\n\n"
        f"📦 Paket: *{user['paket'].upper()}*\n"
        f"⏰ Sisa: *{hari} hari*\n"
        f"📅 Expired: `{user['expired']}`\n\n"
        "*RECON:*\n"
        "/dns `/sub` `/whois` `/ip` `/ssl` `/tech` `/waf` `/shodan` `/dork` `/axfr` `/rev`\n\n"
        "*VULN:*\n"
        "/scan `/sqli` `/xss` `/lfi` `/ssrf` `/redirect` `/cors` `/methods` `/dir`\n\n"
        "*TOOLS:*\n"
        "/base64e `/base64d` `/hash` `/jwt`\n\n"
        "/myaccount — Info akun\n"
        "/paket — Daftar paket\n"
        "/help — Bantuan"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def myaccount_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if is_owner(uid):
        await update.message.reply_text("👑 Kamu adalah owner.")
        return
    if not is_registered(uid):
        await update.message.reply_text("❌ Kamu belum terdaftar.")
        return
    user = get_user(uid)
    hari = sisa_hari(uid)
    text = (
        f"👤 *AKUN KAMU*\n\n"
        f"Nama: *{user['nama']}*\n"
        f"ID: `{user['id']}`\n"
        f"Paket: *{user['paket'].upper()}*\n"
        f"Mulai: `{user['start']}`\n"
        f"Expired: `{user['expired']}`\n"
        f"Sisa: *{hari} hari*\n"
        f"Status: *{user['status']}*"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def paket_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    paket = get_paket_list()
    text = "💎 *DAFTAR PAKET*\n\n"
    for nama, info in paket.items():
        harga = "GRATIS" if info["harga"] == 0 else f"Rp {info['harga']:,}".replace(",", ".")
        text += f"📦 *{nama.upper()}*\n"
        text += f"   Durasi: {info['durasi']} hari\n"
        text += f"   Harga: {harga}\n"
        text += f"   Fitur: {info['fitur']}\n\n"
    text += f"\nUntuk berlangganan, hubungi owner: *{NAMA_OWNER}*"
    await update.message.reply_text(text, parse_mode="Markdown")


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
    text = (
        f"📖 *CARA PAKAI {NAMA_BOT}*\n\n"
        "Kirim perintah dengan argumen.\n"
        "Contoh: `/scan example.com`\n\n"
        "*Info akun:*\n"
        "/myaccount — Info akun kamu\n"
        "/paket — Daftar paket\n\n"
        "*Recon:*\n"
        "/dns `/sub` `/whois` `/ip` `/ssl` `/tech` `/waf` `/shodan` `/dork` `/axfr` `/rev`\n\n"
        "*Vuln:*\n"
        "/scan `/sqli` `/xss` `/lfi` `/ssrf` `/redirect` `/cors` `/methods` `/dir`\n\n"
        "*Tools:*\n"
        "/base64e `/base64d` `/hash` `/jwt`\n\n"
        "⚠️ *Gunakan hanya untuk domain milik Anda.*"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


# ================== OWNER COMMANDS ==================

async def adduser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    args = context.args
    if len(args) < 3:
        await update.message.reply_text(
            "❌ Format: `/adduser <id> <nama> <paket>`\n"
            "Paket: trial / basic / premium / pro / lifetime",
            parse_mode="Markdown"
        )
        return
    try:
        target_id = int(args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    nama = args[1]
    paket = args[2].lower()
    ok, msg = add_user(target_id, nama, paket)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def removeuser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    if not context.args:
        await update.message.reply_text("❌ Format: `/removeuser <id>`", parse_mode="Markdown")
        return
    try:
        target_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    ok, msg = remove_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def extend_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("❌ Format: `/extend <id> <hari>`", parse_mode="Markdown")
        return
    try:
        target_id = int(context.args[0])
        hari = int(context.args[1])
    except:
        await update.message.reply_text("❌ ID dan hari harus angka.")
        return
    ok, msg = extend_user(target_id, hari)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    if not context.args:
        await update.message.reply_text("❌ Format: `/ban <id>`", parse_mode="Markdown")
        return
    try:
        target_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    ok, msg = ban_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    if not context.args:
        await update.message.reply_text("❌ Format: `/unban <id>`", parse_mode="Markdown")
        return
    try:
        target_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    ok, msg = unban_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def listuser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    users = list_users()
    if not users:
        await update.message.reply_text("📭 Belum ada user terdaftar.")
        return
    text = f"👥 *DAFTAR USER* ({len(users)})\n\n"
    for id_str, u in users.items():
        hari = sisa_hari(int(id_str))
        emoji = "🟢" if u["status"] == "active" and hari > 0 else ("🔴" if u["status"] == "banned" else "🟡")
        text += f"{emoji} `{id_str}` — *{u['nama']}* ({u['paket']}) — {hari} hari\n"
    if len(text) > 4000:
        text = text[:4000] + "\n... (dipotong)"
    await update.message.reply_text(text, parse_mode="Markdown")


async def userinfo_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Command ini hanya untuk owner.")
        return
    if not context.args:
        await update.message.reply_text("❌ Format: `/userinfo <id>`", parse_mode="Markdown")
        return
    try:
        target_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    user = get_user(target_id)
    if not user:
        await update.message.reply_text("❌ User tidak ditemukan.")
        return
    hari = sisa_hari(target_id)
    text = (
        f"👤 *USER INFO*\n\n"
        f"ID: `{user['id']}`\n"
        f"Nama: *{user['nama']}*\n"
        f"Paket: *{user['paket'].upper()}*\n"
        f"Fitur: `{user['fitur']}`\n"
        f"Mulai: `{user['start']}`\n"
        f"Expired: `{user['expired']}`\n"
        f"Sisa: *{hari} hari*\n"
        f"Status: *{user['status']}*\n"
        f"Dibuat: `{user['created_at']}`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def setowner_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    current_owner = get_owner_id()
    if current_owner != 0 and not is_owner(uid):
        await update.message.reply_text("❌ Hanya owner yang bisa ganti owner.")
        return
    if not context.args:
        await update.message.reply_text("❌ Format: `/setowner <id>`", parse_mode="Markdown")
        return
    try:
        new_owner = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID harus angka.")
        return
    set_owner_id(new_owner)
    await update.message.reply_text(f"✅ Owner baru: `{new_owner}`", parse_mode="Markdown")


# ================== RECON ==================

async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return

    # Cek fitur (basic tidak bisa scan vuln)
    if not is_owner(uid):
        user = get_user(uid)
        if user["fitur"] == "recon":
            await update.message.reply_text(
                "🔒 *FITUR TERBATAS*\n\n"
                "Paket *BASIC* hanya bisa akses fitur Recon.\n"
                "Upgrade ke *PREMIUM* untuk akses fitur Vuln scan.\n\n"
                f"Hubungi owner: *{NAMA_OWNER}*",
                parse_mode="Markdown"
            )
            return

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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
    if not is_owner(uid):
        user = get_user(uid)
        if user["fitur"] == "recon":
            await update.message.reply_text(
                "🔒 *FITUR TERBATAS*\n\nPaket BASIC hanya Recon.\nUpgrade ke PREMIUM.",
                parse_mode="Markdown"
            )
            return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("❌ Format: `/base64e hello`", parse_mode="Markdown")
        return
    await update.message.reply_text(f"```\n{base64_encode(text)}\n```", parse_mode="Markdown")


async def base64d_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
    text = " ".join(context.args) if context.args else ""
    if not text:
        await update.message.reply_text("❌ Format: `/base64d aGVsbG8=`", parse_mode="Markdown")
        return
    try:
        await update.message.reply_text(f"```\n{base64_decode(text)}\n```", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")


async def hash_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown")
        return
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
        await update.message.reply_text(f"❌ Ketik /start untuk menu {NAMA_BOT}.")


async def error_handler(update, context):
    logger.error(f"Error: {context.error}")


# ================== MAIN ==================

def main():
    if not BOT_TOKEN:
        print("BOT_TOKEN belum di-set di environment")
        return
    app = Application.builder().token(BOT_TOKEN).build()

    # Info & User
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("myaccount", myaccount_cmd))
    app.add_handler(CommandHandler("paket", paket_cmd))

    # Owner
    app.add_handler(CommandHandler("adduser", adduser_cmd))
    app.add_handler(CommandHandler("removeuser", removeuser_cmd))
    app.add_handler(CommandHandler("extend", extend_cmd))
    app.add_handler(CommandHandler("ban", ban_cmd))
    app.add_handler(CommandHandler("unban", unban_cmd))
    app.add_handler(CommandHandler("listuser", listuser_cmd))
    app.add_handler(CommandHandler("userinfo", userinfo_cmd))
    app.add_handler(CommandHandler("setowner", setowner_cmd))

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

    print("DiabloXhunt Private Edition running...")
    print("Owner: Naddd")

    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
