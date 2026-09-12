import os
import json
import logging
import asyncio
import base64
import datetime as dt_mod
from datetime import datetime
from urllib.parse import urlparse

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, ContextTypes,
    CallbackQueryHandler
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
from modules.osint import (
    email_check, phone_check, username_check, github_check,
    telegram_check, domain_info, ip_full_info, mx_lookup,
    subdomain_crtsh, robots_check, headers_check, my_ip,
    virustotal_url_check, virustotal_ip_check,
    hunter_domain_search, ipstack_check, abstract_email_check,
    geoloc_ip, geoloc_ipstack, geocode_search, geocode_opencage,
    reverse_geocode, reverse_geocode_opencage,
    nearby_geoapify, route_geoapify, distance_calc,
)
from database import (
    is_owner, is_registered, is_active, get_user, add_user, remove_user,
    extend_user, ban_user, unban_user, list_users, sisa_hari,
    get_paket_list, set_owner_id, get_owner_id, user_count,
    get_ref_code, get_ref_by_code, get_ref_stats, get_top_referrers,
    get_users_expiring, get_users_expired_today, mark_notified, is_notified,
)

# ================== KONFIGURASI ==================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
NAMA_BOT = "DiabloXhunt"
NAMA_OWNER = "Naddd"
OWNER_USERNAME = "ZerooTwo2"
VERSION = "2.3"
BANNER_URL = os.getenv("BANNER_URL", "https://i.imgur.com/pp1gIFY.jpeg")
# =================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ================== HELPER ==================

def owner_link() -> str:
    return f"[{NAMA_OWNER}](https://t.me/{OWNER_USERNAME})"


def owner_button() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton(
            f"💬 Chat Owner @{OWNER_USERNAME}",
            url=f"https://t.me/{OWNER_USERNAME}"
        )]
    ]
    return InlineKeyboardMarkup(keyboard)


def cek_akses(uid):
    if is_owner(uid):
        return "owner", ""
    if not is_registered(uid):
        return "unregistered", (
            "╔══════════════════════╗\n"
            "║  🔒 *AKSES DITOLAK*  ║\n"
            "╚══════════════════════╝\n\n"
            "Kamu belum terdaftar.\n\n"
            "📝  Cara daftar:\n"
            "     `/register <nama>`\n\n"
            "💎  Untuk berlangganan:\n"
            f"     Owner: {owner_link()}\n\n"
            "Ketik /paket untuk lihat paket."
        )
    if not is_active(uid):
        user = get_user(uid)
        if user and user.get("status") == "banned":
            return "banned", (
                "╔══════════════════════╗\n"
                "║  🚫 *DIBANNED*       ║\n"
                "╚══════════════════════╝\n\n"
                "Akun kamu telah dibanned.\n\n"
                f"Hubungi owner: {owner_link()}"
            )
        return "expired", (
            "╔══════════════════════╗\n"
            "║  ⏰ *EXPIRED*        ║\n"
            "╚══════════════════════╝\n\n"
            "Langganan kamu sudah habis.\n\n"
            f"📅  Expired: `{user['expired'] if user else '-'}`\n\n"
            f"Perpanjang ke owner: {owner_link()}"
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


# ================== KEYBOARD MENUS ==================

def main_menu_keyboard(uid):
    keyboard = []
    if is_owner(uid):
        keyboard.append([InlineKeyboardButton("👑 Owner Panel", callback_data="menu_owner")])
    keyboard.extend([
        [InlineKeyboardButton("🕵️ OSINT Tools", callback_data="menu_osint")],
        [InlineKeyboardButton("🔍 Recon Tools", callback_data="menu_recon")],
        [InlineKeyboardButton("💥 Vuln Scanner", callback_data="menu_vuln")],
        [InlineKeyboardButton("🧰 Tools & Utility", callback_data="menu_tools")],
        [InlineKeyboardButton("📍 Geolocation", callback_data="menu_geo")],
        [
            InlineKeyboardButton("👤 Akun Saya", callback_data="menu_akun"),
            InlineKeyboardButton("💎 Paket", callback_data="menu_paket"),
        ],
        [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
    ])
    return InlineKeyboardMarkup(keyboard)


def osint_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📧 Email", callback_data="osint_email"),
            InlineKeyboardButton("📱 Phone", callback_data="osint_phone"),
        ],
        [
            InlineKeyboardButton("👤 Username", callback_data="osint_username"),
            InlineKeyboardButton("🐙 GitHub", callback_data="osint_github"),
        ],
        [
            InlineKeyboardButton("✈️ Telegram", callback_data="osint_telegram"),
            InlineKeyboardButton("📡 IP Info", callback_data="osint_ipinfo"),
        ],
        [
            InlineKeyboardButton("📬 MX Check", callback_data="osint_mx"),
            InlineKeyboardButton("🔍 Subdomain", callback_data="osint_subdomain"),
        ],
        [
            InlineKeyboardButton("🤖 Robots.txt", callback_data="osint_robots"),
            InlineKeyboardButton("🛡️ Headers", callback_data="osint_headers"),
        ],
        [InlineKeyboardButton("🌐 My IP", callback_data="osint_myip")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def recon_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 DNS", callback_data="recon_dns"),
            InlineKeyboardButton("🔎 Subdomain", callback_data="recon_sub"),
        ],
        [
            InlineKeyboardButton("📋 WHOIS", callback_data="recon_whois"),
            InlineKeyboardButton("🌍 IP", callback_data="recon_ip"),
        ],
        [
            InlineKeyboardButton("🔒 SSL", callback_data="recon_ssl"),
            InlineKeyboardButton("🔧 Tech", callback_data="recon_tech"),
        ],
        [
            InlineKeyboardButton("🛡️ WAF", callback_data="recon_waf"),
            InlineKeyboardButton("🔭 Shodan", callback_data="recon_shodan"),
        ],
        [
            InlineKeyboardButton("🕵️ Dork", callback_data="recon_dork"),
            InlineKeyboardButton("📡 AXFR", callback_data="recon_axfr"),
        ],
        [InlineKeyboardButton("🔄 Reverse DNS", callback_data="recon_rev")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def vuln_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Full Scan", callback_data="vuln_scan")],
        [
            InlineKeyboardButton("💉 SQLi", callback_data="vuln_sqli"),
            InlineKeyboardButton("🎯 XSS", callback_data="vuln_xss"),
        ],
        [
            InlineKeyboardButton("📂 LFI", callback_data="vuln_lfi"),
            InlineKeyboardButton("🌐 SSRF", callback_data="vuln_ssrf"),
        ],
        [
            InlineKeyboardButton("🔀 Redirect", callback_data="vuln_redirect"),
            InlineKeyboardButton("🔓 CORS", callback_data="vuln_cors"),
        ],
        [
            InlineKeyboardButton("⚙️ Methods", callback_data="vuln_methods"),
            InlineKeyboardButton("📁 Dir", callback_data="vuln_dir"),
        ],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def tools_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔐 Base64 Encode", callback_data="tools_base64e"),
            InlineKeyboardButton("🔓 Base64 Decode", callback_data="tools_base64d"),
        ],
        [
            InlineKeyboardButton("#️⃣ Hash", callback_data="tools_hash"),
            InlineKeyboardButton("🎫 JWT Decode", callback_data="tools_jwt"),
        ],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def geo_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📍 Geoloc IP", callback_data="geo_geoloc2"),
            InlineKeyboardButton("🗺️ Geocode", callback_data="geo_geocode"),
        ],
        [
            InlineKeyboardButton("🔄 Reverse Geo", callback_data="geo_revgeo"),
            InlineKeyboardButton("🏪 Nearby", callback_data="geo_nearby"),
        ],
        [
            InlineKeyboardButton("🚗 Route", callback_data="geo_route"),
            InlineKeyboardButton("📏 Distance", callback_data="geo_distance"),
        ],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def owner_menu_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("➕ Add User", callback_data="owner_adduser"),
            InlineKeyboardButton("➖ Remove", callback_data="owner_removeuser"),
        ],
        [
            InlineKeyboardButton("⏱️ Extend", callback_data="owner_extend"),
            InlineKeyboardButton("🚫 Ban", callback_data="owner_ban"),
        ],
        [
            InlineKeyboardButton("✅ Unban", callback_data="owner_unban"),
            InlineKeyboardButton("📋 List User", callback_data="owner_listuser"),
        ],
        [
            InlineKeyboardButton("🔍 User Info", callback_data="owner_userinfo"),
            InlineKeyboardButton("🔄 Cek Expired", callback_data="owner_cekexpired"),
        ],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def paket_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🎁 Trial (FREE)", callback_data="buy_trial"),
            InlineKeyboardButton("🥉 Basic (10rb)", callback_data="buy_basic"),
        ],
        [
            InlineKeyboardButton("🥈 Premium (25rb)", callback_data="buy_premium"),
            InlineKeyboardButton("🥇 Pro (50rb)", callback_data="buy_pro"),
        ],
        [InlineKeyboardButton("👑 Lifetime (200rb)", callback_data="buy_lifetime")],
        [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])
    

# ================== START ==================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)

    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(
            pesan, parse_mode="Markdown", reply_markup=owner_button()
        )
        return

    user = get_user(uid) if not is_owner(uid) else None
    hari = sisa_hari(uid) if user else 0

    if is_owner(uid):
        caption = (
            "╔══════════════════════╗\n"
            "║  👑 *DIABLOX HUNT*   ║\n"
            "║  *OWNER ACCESS*      ║\n"
            "╚══════════════════════╝\n\n"
            f"👑 *Owner* : `{NAMA_OWNER}`\n"
            f"📡 *Status*: 🟢 `ONLINE`\n"
            f"👥 *Users* : `{user_count()}`\n"
            f"🔧 *Versi* : `v{VERSION}`\n\n"
            "✨ *Pilih menu di bawah:*"
        )
    else:
        caption = (
            "╔══════════════════════╗\n"
            "║  🛡️ *DIABLOX HUNT*   ║\n"
            "║  *USER ACCESS*       ║\n"
            "╚══════════════════════╝\n\n"
            f"👋 Halo, *{user['nama']}*!\n\n"
            f"📦 *Paket*  : `{user['paket'].upper()}`\n"
            f"⏰ *Sisa*   : `{hari} hari`\n"
            f"📅 *Expired*: `{user['expired']}`\n"
            f"🚦 *Status* : 🟢 `ACTIVE`\n\n"
            "✨ *Pilih menu di bawah:*"
        )

    try:
        await update.message.reply_photo(
            photo=BANNER_URL,
            caption=caption,
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(uid)
        )
    except Exception as e:
        logger.error(f"Banner error: {e}")
        await update.message.reply_text(
            caption, parse_mode="Markdown",
            reply_markup=main_menu_keyboard(uid)
        )


# ================== CALLBACK HANDLER ==================

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id

    if not is_owner(uid):
        status, pesan = cek_akses(uid)
        if status in ("unregistered", "banned", "expired"):
            try:
                await query.edit_message_caption(
                    caption=pesan, parse_mode="Markdown", reply_markup=owner_button()
                )
            except:
                await query.edit_message_text(
                    pesan, parse_mode="Markdown", reply_markup=owner_button()
                )
            return

    user = get_user(uid) if not is_owner(uid) else None
    hari = sisa_hari(uid) if user else 0

    def header(title, emoji="✨"):
        return (
            "╔══════════════════════╗\n"
            f"║  {emoji} *{title}*  ║\n"
            "╚══════════════════════╝\n\n"
        )

    async def edit_caption(caption, keyboard):
        try:
            await query.edit_message_caption(
                caption=caption, parse_mode="Markdown", reply_markup=keyboard
            )
        except:
            await query.edit_message_text(
                caption, parse_mode="Markdown", reply_markup=keyboard
            )

    # ============ MAIN ============
    if data == "menu_main":
        if is_owner(uid):
            caption = (
                header("OWNER ACCESS", "👑") +
                f"👑 *Owner* : `{NAMA_OWNER}`\n"
                f"📡 *Status*: 🟢 `ONLINE`\n"
                f"👥 *Users* : `{user_count()}`\n"
                f"🔧 *Versi* : `v{VERSION}`\n\n"
                "✨ *Pilih menu:*"
            )
        else:
            caption = (
                header("DIABLOX HUNT", "🛡️") +
                f"👋 Halo, *{user['nama']}*!\n\n"
                f"📦 *Paket*  : `{user['paket'].upper()}`\n"
                f"⏰ *Sisa*   : `{hari} hari`\n"
                f"🚦 *Status* : 🟢 `ACTIVE`\n\n"
                "✨ *Pilih menu:*"
            )
        await edit_caption(caption, main_menu_keyboard(uid))
        return

    # ============ SUBMENUS ============
    if data == "menu_osint":
        caption = (
            header("OSINT TOOLS", "🕵️") +
            "📧 *Email*        — Cek email & MX\n"
            "📱 *Phone*        — Cek nomor HP\n"
            "👤 *Username*     — Cari di 24 platform\n"
            "🐙 *GitHub*       — Info user GitHub\n"
            "✈️ *Telegram*     — Cek username TG\n"
            "📡 *IP Info*      — Geolokasi IP\n"
            "📬 *MX Check*     — MX/SPF/DMARC\n"
            "🔍 *Subdomain*    — Cari subdomain\n"
            "🤖 *Robots.txt*   — Ambil robots.txt\n"
            "🛡️ *Headers*      — Security headers\n"
            "🌐 *My IP*        — Cek IP kamu\n\n"
            "⚠️ _Klik tombol untuk pakai_"
        )
        await edit_caption(caption, osint_menu_keyboard())
        return

    if data == "menu_recon":
        caption = (
            header("RECON TOOLS", "🔍") +
            "🌐 *DNS*         — DNS enumeration\n"
            "🔎 *Subdomain*   — Subdomain scan\n"
            "📋 *WHOIS*       — Info domain\n"
            "🌍 *IP*          — Info IP\n"
            "🔒 *SSL*         — Cek sertifikat\n"
            "🔧 *Tech*        — Deteksi teknologi\n"
            "🛡️ *WAF*         — Deteksi WAF\n"
            "🔭 *Shodan*      — Info server\n"
            "🕵️ *Dork*        — Google dorks\n"
            "📡 *AXFR*        — Zone transfer\n"
            "🔄 *Reverse*     — Reverse DNS\n\n"
            "⚠️ _Klik tombol untuk pakai_"
        )
        await edit_caption(caption, recon_menu_keyboard())
        return

    if data == "menu_vuln":
        if not is_owner(uid) and user and user["fitur"] == "recon":
            await query.answer("🔒 Paket BASIC hanya Recon. Upgrade ke PREMIUM!", show_alert=True)
            return
        caption = (
            header("VULN SCANNER", "💥") +
            "🚀 *Full Scan*   — Semua kerentanan\n"
            "💉 *SQLi*        — SQL Injection\n"
            "🎯 *XSS*         — Cross-Site Scripting\n"
            "📂 *LFI*         — Local File Inclusion\n"
            "🌐 *SSRF*        — Server-Side Request\n"
            "🔀 *Redirect*    — Open Redirect\n"
            "🔓 *CORS*        — CORS misconfig\n"
            "⚙️ *Methods*     — HTTP methods\n"
            "📁 *Dir*         — Directory bruteforce\n\n"
            "⚠️ _Gunakan hanya untuk domain sendiri_"
        )
        await edit_caption(caption, vuln_menu_keyboard())
        return

    if data == "menu_tools":
        caption = (
            header("TOOLS & UTILITY", "🧰") +
            "🔐 *Base64 Encode*  — Encode text\n"
            "🔓 *Base64 Decode*  — Decode base64\n"
            "#️⃣ *Hash*           — MD5/SHA1/SHA256\n"
            "🎫 *JWT Decode*     — Decode JWT token\n\n"
            "⚠️ _Klik tombol untuk pakai_"
        )
        await edit_caption(caption, tools_menu_keyboard())
        return

    if data == "menu_geo":
        caption = (
            header("GEOLOCATION", "📍") +
            "📍 *Geoloc IP*    — Lacak IP\n"
            "🗺️ *Geocode*     — Nama → koordinat\n"
            "🔄 *Reverse Geo* — Koordinat → alamat\n"
            "🏪 *Nearby*      — Tempat terdekat\n"
            "🚗 *Route*       — Rute A → B\n"
            "📏 *Distance*    — Jarak 2 titik\n\n"
            "⚠️ _Klik tombol untuk pakai_"
        )
        await edit_caption(caption, geo_menu_keyboard())
        return

    if data == "menu_owner":
        if not is_owner(uid):
            await query.answer("❌ Hanya owner!", show_alert=True)
            return
        caption = (
            header("OWNER PANEL", "👑") +
            f"📊 *Total User*: `{user_count()}`\n\n"
            "➕ *Add User*     — Tambah user\n"
            "➖ *Remove*       — Hapus user\n"
            "⏱️ *Extend*       — Perpanjang\n"
            "🚫 *Ban*          — Ban user\n"
            "✅ *Unban*        — Unban user\n"
            "📋 *List User*    — Daftar user\n"
            "🔍 *User Info*    — Info user\n"
            "🔄 *Cek Expired*  — Manual cek\n\n"
            "⚠️ _Klik tombol untuk pakai_"
        )
        await edit_caption(caption, owner_menu_keyboard())
        return

    if data == "menu_akun":
        if is_owner(uid):
            await query.answer("👑 Kamu owner!", show_alert=True)
            return
        caption = (
            header("AKUN SAYA", "👤") +
            f"🆔 *ID*      : `{user['id']}`\n"
            f"📛 *Nama*    : *{user['nama']}*\n"
            f"📦 *Paket*   : `{user['paket'].upper()}`\n"
            f"🎯 *Fitur*   : `{user['fitur']}`\n"
            f"📅 *Mulai*   : `{user['start']}`\n"
            f"⏰ *Expired* : `{user['expired']}`\n"
            f"⏳ *Sisa*    : *{hari} hari*\n"
            f"🚦 *Status*  : 🟢 `{user['status'].upper()}`\n"
            f"🎫 *Ref*     : `{user.get('ref_code', '-')}`\n"
        )
        await edit_caption(caption, InlineKeyboardMarkup([
            [InlineKeyboardButton("🎁 My Referral", callback_data="menu_myref")],
            [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
        ]))
        return

    if data == "menu_myref":
        stats = get_ref_stats(uid) or {"code": "-", "count": 0, "history": []}
        caption = (
            header("REFERRAL", "🎁") +
            f"🎫 *Kode Kamu*:\n`{stats['code']}`\n\n"
            f"📊 *Total Referral*: *{stats['count']}*\n"
            f"🎁 *Bonus per Ref* : *+7 hari*\n\n"
            "📖 *Cara Pakai:*\n"
            f"1. Share kode `{stats['code']}`\n"
            "2. Teman kirim `/register <nama> <kode>`\n"
            "3. Teman dapat *+3 hari*\n"
            "4. Kamu dapat *+7 hari*\n"
        )
        await edit_caption(caption, InlineKeyboardMarkup([
            [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_akun")],
        ]))
        return

    if data == "menu_paket":
        paket = get_paket_list()
        caption = header("DAFTAR PAKET", "💎")
        emoji_map = {"trial": "🎁", "basic": "🥉", "premium": "🥈",
                     "pro": "🥇", "lifetime": "👑"}
        for nama, info in paket.items():
            harga = "GRATIS" if info["harga"] == 0 else f"Rp {info['harga']:,}".replace(",", ".")
            caption += f"{emoji_map.get(nama, '📦')} *{nama.upper()}* — {info['durasi']} hari — *{harga}*\n"
        caption += "\n💬 _Klik tombol untuk beli atau chat owner_"
        await edit_caption(caption, paket_keyboard())
        return

    # ============ COMMAND PROMPTS ============
    prompts = {
        "osint_email": "📧 Kirim: `/email nama@domain.com`",
        "osint_phone": "📱 Kirim: `/phone +628123456789`",
        "osint_username": "👤 Kirim: `/username namauser`",
        "osint_github": "🐙 Kirim: `/github username`",
        "osint_telegram": "✈️ Kirim: `/telegram username`",
        "osint_ipinfo": "📡 Kirim: `/ipinfo 8.8.8.8`",
        "osint_mx": "📬 Kirim: `/mx example.com`",
        "osint_subdomain": "🔍 Kirim: `/subdomain example.com`",
        "osint_robots": "🤖 Kirim: `/robots example.com`",
        "osint_headers": "🛡️ Kirim: `/headers example.com`",
        "osint_myip": "🌐 Kirim: `/myip`",
        "recon_dns": "🌐 Kirim: `/dns example.com`",
        "recon_sub": "🔎 Kirim: `/sub example.com`",
        "recon_whois": "📋 Kirim: `/whois example.com`",
        "recon_ip": "🌍 Kirim: `/ip 8.8.8.8`",
        "recon_ssl": "🔒 Kirim: `/ssl example.com`",
        "recon_tech": "🔧 Kirim: `/tech https://example.com`",
        "recon_waf": "🛡️ Kirim: `/waf https://example.com`",
        "recon_shodan": "🔭 Kirim: `/shodan 8.8.8.8`",
        "recon_dork": "🕵️ Kirim: `/dork example.com`",
        "recon_axfr": "📡 Kirim: `/axfr example.com`",
        "recon_rev": "🔄 Kirim: `/rev 8.8.8.8`",
        "vuln_scan": "🚀 Kirim: `/scan example.com`",
        "vuln_sqli": "💉 Kirim: `/sqli https://example.com/page?id=1`",
        "vuln_xss": "🎯 Kirim: `/xss https://example.com/search?q=test`",
        "vuln_lfi": "📂 Kirim: `/lfi https://example.com/file?name=index`",
        "vuln_ssrf": "🌐 Kirim: `/ssrf https://example.com/fetch?url=test`",
        "vuln_redirect": "🔀 Kirim: `/redirect https://example.com/redir?url=x`",
        "vuln_cors": "🔓 Kirim: `/cors https://example.com`",
        "vuln_methods": "⚙️ Kirim: `/methods https://example.com`",
        "vuln_dir": "📁 Kirim: `/dir https://example.com`",
        "tools_base64e": "🔐 Kirim: `/base64e hello`",
        "tools_base64d": "🔓 Kirim: `/base64d aGVsbG8=`",
        "tools_hash": "#️⃣ Kirim: `/hash hello`",
        "tools_jwt": "🎫 Kirim: `/jwt eyJhbG...`",
        "geo_geoloc2": "📍 Kirim: `/geoloc2 8.8.8.8`",
        "geo_geocode": "🗺️ Kirim: `/geocode Monas Jakarta`",
        "geo_revgeo": "🔄 Kirim: `/revgeo -6.1754 106.8272`",
        "geo_nearby": "🏪 Kirim: `/nearby -6.1754 106.8272 restaurant`",
        "geo_route": "🚗 Kirim: `/route -6.1754 106.8272 -6.2088 106.8456`",
        "geo_distance": "📏 Kirim: `/distance -6.1754 106.8272 -6.2088 106.8456`",
        "owner_adduser": "➕ Kirim: `/adduser <id> <nama> <paket>`",
        "owner_removeuser": "➖ Kirim: `/removeuser <id>`",
        "owner_extend": "⏱️ Kirim: `/extend <id> <hari>`",
        "owner_ban": "🚫 Kirim: `/ban <id>`",
        "owner_unban": "✅ Kirim: `/unban <id>`",
        "owner_listuser": "📋 Kirim: `/listuser`",
        "owner_userinfo": "🔍 Kirim: `/userinfo <id>`",
        "owner_cekexpired": "🔄 Kirim: `/cekexpired`",
    }

    if data in prompts:
        try:
            await query.edit_message_caption(
                caption=f"📝 *PROMPT*\n\n{prompts[data]}\n\n_Ketik perintah di chat._",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
                ])
            )
        except:
            await query.edit_message_text(
                f"📝 *PROMPT*\n\n{prompts[data]}\n\n_Ketik perintah di chat._",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
                ])
            )
        return

    # ============ BUY PAKET ============
    if data.startswith("buy_"):
        paket_nama = data.replace("buy_", "")
        paket = get_paket_list().get(paket_nama, {})
        harga = "GRATIS" if paket.get("harga") == 0 else f"Rp {paket.get('harga', 0):,}".replace(",", ".")
        caption = (
            header("BELI PAKET", "💎") +
            f"📦 Paket  : *{paket_nama.upper()}*\n"
            f"⏱️ Durasi : `{paket.get('durasi', '-')} hari`\n"
            f"💰 Harga  : *{harga}*\n"
            f"🎯 Fitur  : `{paket.get('fitur', '-')}`\n\n"
            "📞 *Hubungi owner untuk bayar:*\n"
            f"💬 {owner_link()}\n\n"
            "_Setelah bayar, owner akan aktivasi akun kamu._"
        )
        await edit_caption(caption, InlineKeyboardMarkup([
            [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
            [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_paket")],
        ]))
        return
        

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
    ok, msg = add_user(target_id, args[1], args[2].lower())
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def removeuser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Hanya owner.")
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
        await update.message.reply_text("❌ Hanya owner.")
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
        await update.message.reply_text("❌ Hanya owner.")
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
        await update.message.reply_text("❌ Hanya owner.")
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
        await update.message.reply_text("❌ Hanya owner.")
        return
    users = list_users()
    if not users:
        await update.message.reply_text("📭 Belum ada user.")
        return
    text = f"╔══════════════════════╗\n║  👥 *USER LIST*       ║\n╚══════════════════════╝\n\n"
    for id_str, u in users.items():
        hari = sisa_hari(int(id_str))
        emoji = "🚫" if u["status"] == "banned" else ("🟢" if hari > 0 else "🔴")
        text += f"{emoji} *{u['nama']}* — {u['paket']} — {hari}h\n   🆔 `{id_str}`\n▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n"
    if len(text) > 4000:
        text = text[:4000] + "\n..."
    await update.message.reply_text(text, parse_mode="Markdown")


async def userinfo_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Hanya owner.")
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
        "╔══════════════════════╗\n"
        "║  👤 *USER INFO*      ║\n"
        "╚══════════════════════╝\n\n"
        f"🆔 ID: `{user['id']}`\n"
        f"📛 Nama: *{user['nama']}*\n"
        f"📦 Paket: `{user['paket'].upper()}`\n"
        f"🎯 Fitur: `{user['fitur']}`\n"
        f"📅 Mulai: `{user['start']}`\n"
        f"⏰ Expired: `{user['expired']}`\n"
        f"⏳ Sisa: *{hari} hari*\n"
        f"🚦 Status: `{user['status'].upper()}`\n"
        f"🎫 Ref: `{user.get('ref_code', '-')}`\n"
        f"👥 Ref Count: *{user.get('ref_count', 0)}*\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def setowner_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if get_owner_id() != 0 and not is_owner(uid):
        await update.message.reply_text("❌ Hanya owner.")
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
    

# ================== REFERRAL ==================

async def myref_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if is_owner(uid):
        stats = get_ref_stats(uid) or {"code": "-", "count": 0, "history": []}
    else:
        status, pesan = cek_akses(uid)
        if status in ("unregistered", "banned", "expired"):
            await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
            return
        stats = get_ref_stats(uid)
        if not stats:
            await update.message.reply_text("❌ Kamu belum terdaftar.")
            return
    text = (
        "╔══════════════════════╗\n"
        "║  🎁 *REFERRAL*        ║\n"
        "╚══════════════════════╝\n\n"
        f"🎫 *Kode Kamu*:\n`{stats['code']}`\n\n"
        f"📊 Total Referral: *{stats['count']}*\n"
        f"🎁 Bonus per Ref: *+7 hari*\n\n"
        f"📖 *Cara Pakai:*\n"
        f"1. Share kode `{stats['code']}`\n"
        f"2. Teman kirim `/register <nama> {stats['code']}`\n"
        f"3. Teman dapat *+3 hari*\n"
        f"4. Kamu dapat *+7 hari*\n"
    )
    if stats["history"]:
        text += "\n📜 *Riwayat:*\n"
        for h in stats["history"][-5:]:
            text += f"• {h['nama']} — +{h['reward']} hari\n"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=owner_button())


async def topref_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        status, pesan = cek_akses(uid)
        if status in ("unregistered", "banned", "expired"):
            await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
            return
    top = get_top_referrers(10)
    if not top:
        await update.message.reply_text("📭 Belum ada referral.")
        return
    text = "╔══════════════════════╗\n║  🏆 *TOP REFERRERS*   ║\n╚══════════════════════╝\n\n"
    for i, (uid_str, user) in enumerate(top, 1):
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f" {i}."
        text += f"{medal} *{user['nama']}* — {user['ref_count']} ref\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def register_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if is_owner(uid):
        await update.message.reply_text("👑 Kamu owner.")
        return
    if is_registered(uid):
        await update.message.reply_text("✅ Kamu sudah terdaftar.")
        return
    args = context.args
    if len(args) < 1:
        await update.message.reply_text(
            "❌ Format: `/register <nama>` atau `/register <nama> <kode_ref>`",
            parse_mode="Markdown"
        )
        return
    nama = args[0]
    ref_code = args[1] if len(args) > 1 else None
    referred_by = None
    if ref_code:
        referred_by = get_ref_by_code(ref_code)
        if not referred_by:
            await update.message.reply_text(
                f"⚠️ Kode `{ref_code}` tidak valid.\n"
                f"Lanjut tanpa referral? Ketik `/register {nama}`",
                parse_mode="Markdown"
            )
            return
    ok, msg = add_user(uid, nama, "trial", hari=0, referred_by=referred_by)
    if ok:
        text = (
            "╔══════════════════════╗\n"
            "║  ✅ *REGISTRASI*      ║\n"
            "╚══════════════════════╝\n\n"
            f"📛 Nama: *{nama}*\n"
            f"📦 Paket: *TRIAL*\n"
            f"🚦 Status: *MENUNGGU AKTIVASI*\n\n"
            f"Hubungi owner: {owner_link()}\n\n"
            "Ketik /paket untuk lihat paket."
        )
        if referred_by:
            text += "\n\n🎁 Kamu dapat *+3 hari bonus* dari referral!"
        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=owner_button())
    else:
        await update.message.reply_text(f"❌ {msg}")


# ================== NOTIFIKASI EXPIRED ==================

async def cek_expired_job(context: ContextTypes.DEFAULT_TYPE):
    try:
        for uid, user in get_users_expiring(3):
            if is_notified(uid, "h3"):
                continue
            try:
                await context.bot.send_message(
                    chat_id=int(uid),
                    text=(
                        "╔══════════════════════╗\n"
                        "║  ⏰ *REMINDER*        ║\n"
                        "╚══════════════════════╝\n\n"
                        f"Halo *{user['nama']}*,\n"
                        "Langganan kamu expired dalam *3 hari*.\n\n"
                        f"📅 `{user['expired']}`\n"
                        f"📦 {user['paket'].upper()}\n\n"
                        f"Perpanjang? {owner_link()}"
                    ),
                    parse_mode="Markdown",
                    reply_markup=owner_button()
                )
                mark_notified(uid, "h3")
            except Exception as e:
                logger.error(f"Notif H-3 ke {uid}: {e}")

        for uid, user in get_users_expiring(1):
            if is_notified(uid, "h1"):
                continue
            try:
                await context.bot.send_message(
                    chat_id=int(uid),
                    text=(
                        "╔══════════════════════╗\n"
                        "║  ⚠️ *BESOK EXPIRED*   ║\n"
                        "╚══════════════════════╝\n\n"
                        f"Halo *{user['nama']}*,\n"
                        "Langganan kamu expired *BESOK*.\n\n"
                        f"📅 `{user['expired']}`\n\n"
                        f"Perpanjang: {owner_link()}"
                    ),
                    parse_mode="Markdown",
                    reply_markup=owner_button()
                )
                mark_notified(uid, "h1")
            except Exception as e:
                logger.error(f"Notif H-1 ke {uid}: {e}")

        for uid, user in get_users_expired_today():
            if is_notified(uid, "exp"):
                continue
            try:
                await context.bot.send_message(
                    chat_id=int(uid),
                    text=(
                        "╔══════════════════════╗\n"
                        "║  🔴 *EXPIRED*         ║\n"
                        "╚══════════════════════╝\n\n"
                        f"Halo *{user['nama']}*,\n"
                        "Langganan kamu sudah *EXPIRED*.\n\n"
                        f"Perpanjang: {owner_link()}"
                    ),
                    parse_mode="Markdown",
                    reply_markup=owner_button()
                )
                mark_notified(uid, "exp")
            except Exception as e:
                logger.error(f"Notif expired ke {uid}: {e}")
    except Exception as e:
        logger.error(f"Error cek_expired_job: {e}")


async def cekexpired_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_owner(uid):
        await update.message.reply_text("❌ Hanya owner.")
        return
    msg = await update.message.reply_text("🔄 Cek user expired...")
    await cek_expired_job(context)
    await msg.edit_text("✅ Selesai cek expired.")
    

# ================== RECON ==================

async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
        return
    if not is_owner(uid):
        user = get_user(uid)
        if user and user["fitur"] == "recon":
            await update.message.reply_text(
                "╔══════════════════════╗\n"
                "║  🔒 *FITUR TERBATAS*  ║\n"
                "╚══════════════════════╝\n\n"
                "Paket *BASIC* hanya Recon.\n"
                "Upgrade ke *PREMIUM* untuk vuln scan.\n\n"
                f"Hubungi: {owner_link()}",
                parse_mode="Markdown",
                reply_markup=owner_button()
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
        return
    if not is_owner(uid):
        user = get_user(uid)
        if user and user["fitur"] == "recon":
            await update.message.reply_text(
                "🔒 *FITUR TERBATAS*\n\nPaket BASIC hanya Recon.\nUpgrade ke PREMIUM.",
                parse_mode="Markdown",
                reply_markup=owner_button()
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
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
        print("❌ BOT_TOKEN belum di-set di environment")
        return
    app = Application.builder().token(BOT_TOKEN).build()

    # Info & User
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("myaccount", myaccount_cmd))
    app.add_handler(CommandHandler("paket", paket_cmd))
    app.add_handler(CommandHandler("owner", owner_cmd))

    # Referral
    app.add_handler(CommandHandler("myref", myref_cmd))
    app.add_handler(CommandHandler("topref", topref_cmd))
    app.add_handler(CommandHandler("register", register_cmd))

    # Owner
    app.add_handler(CommandHandler("adduser", adduser_cmd))
    app.add_handler(CommandHandler("removeuser", removeuser_cmd))
    app.add_handler(CommandHandler("extend", extend_cmd))
    app.add_handler(CommandHandler("ban", ban_cmd))
    app.add_handler(CommandHandler("unban", unban_cmd))
    app.add_handler(CommandHandler("listuser", listuser_cmd))
    app.add_handler(CommandHandler("userinfo", userinfo_cmd))
    app.add_handler(CommandHandler("setowner", setowner_cmd))
    app.add_handler(CommandHandler("cekexpired", cekexpired_cmd))

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

    # OSINT
    app.add_handler(CommandHandler("email", email_cmd))
    app.add_handler(CommandHandler("phone", phone_cmd))
    app.add_handler(CommandHandler("username", username_cmd))
    app.add_handler(CommandHandler("github", github_cmd))
    app.add_handler(CommandHandler("telegram", telegram_cmd))
    app.add_handler(CommandHandler("ipinfo", ipinfo_cmd))
    app.add_handler(CommandHandler("mx", mx_cmd))
    app.add_handler(CommandHandler("subdomain", subdomain_cmd))
    app.add_handler(CommandHandler("robots", robots_cmd))
    app.add_handler(CommandHandler("headers", headers_cmd))
    app.add_handler(CommandHandler("myip", myip_cmd))

    # Callback menu tombol
    app.add_handler(CallbackQueryHandler(menu_callback))

    # Text handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    # Job harian cek expired (jam 9 pagi)
    try:
        job_queue = app.job_queue
        job_queue.run_daily(
            cek_expired_job,
            time=dt_mod.time(hour=9, minute=0),
        )
        logger.info("Job queue: cek expired harian jam 09:00")
    except Exception as e:
        logger.error(f"Gagal setup JobQueue: {e}")

    print("DiabloXhunt Private Edition running...")
    print("Owner: Naddd")
    print(f"Owner Username: @{OWNER_USERNAME}")

    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()



    
