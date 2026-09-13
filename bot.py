import os
from dotenv import load_dotenv
load_dotenv()

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

# ===== OSINT MODULES =====
from modules.osint_phone import scan_phone
from modules.osint_email import scan_email
from modules.osint_username import scan_username
from modules.osint_ip import scan_ip
from modules.osint_nik import scan_nik
from modules.osint_rekening import scan_rekening
from modules.osint_instagram import scan_ig
from modules.osint_telegram import scan_telegram
from modules.osint_extra import (
    scan_pastebin, scan_exif, scan_shodan_domain,
    scan_subdomain_history, scan_leakcheck, scan_phonetrack,
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
OWNER_ID = 5728930563  # <-- GANTI KE ID TELEGRAM KAMU
VERSION = "2.8"
BANNER_URL = os.getenv("BANNER_URL", "https://i.imgur.com/pp1gIFY.jpeg")
# =================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def owner_link() -> str:
    return f"[{NAMA_OWNER}](https://t.me/{OWNER_USERNAME})"


def owner_button() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(
            f"💬 Chat Owner @{OWNER_USERNAME}",
            url=f"https://t.me/{OWNER_USERNAME}"
        )]
    ])


def is_owner_uid(uid):
    return uid == OWNER_ID or is_owner(uid)


def cek_akses(uid):
    if is_owner_uid(uid):
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


def cek_akses_osint(uid):
    """Akses OSINT: owner, paket pro, atau lifetime."""
    if is_owner_uid(uid):
        return True, ""
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        return False, pesan
    user = get_user(uid)
    if user and user.get("paket", "").lower() in ("pro", "lifetime"):
        return True, ""
    return False, (
        "╔══════════════════════╗\n"
        "║  🔒 *AKSES TERBATAS* ║\n"
        "╚══════════════════════╝\n\n"
        "Menu *OSINT Tools* hanya untuk:\n"
        "🥇 Paket *PRO*\n"
        "👑 Paket *LIFETIME*\n\n"
        f"Upgrade ke owner: {owner_link()}"
    )


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


async def safe_edit(query, caption, keyboard=None):
    try:
        await query.edit_message_caption(
            caption=caption, parse_mode="Markdown", reply_markup=keyboard
        )
    except Exception:
        try:
            await query.edit_message_text(
                caption, parse_mode="Markdown", reply_markup=keyboard
            )
        except Exception as e:
            logger.warning(f"safe_edit gagal: {e}")


# ================== KEYBOARD MENUS ==================

def main_menu_keyboard(uid):
    keyboard = []
    if is_owner_uid(uid):
        keyboard.append([InlineKeyboardButton("👑 Owner Panel", callback_data="menu_owner")])
    keyboard.extend([
        [InlineKeyboardButton("🔍 Recon Tools", callback_data="menu_recon")],
        [InlineKeyboardButton("💥 Vuln Scanner", callback_data="menu_vuln")],
        [InlineKeyboardButton("🕵️ OSINT Tools", callback_data="menu_osint")],
        [InlineKeyboardButton("🧰 Tools & Utility", callback_data="menu_tools")],
    ])
    keyboard.extend([
        [
            InlineKeyboardButton("👤 Akun Saya", callback_data="menu_akun"),
            InlineKeyboardButton("💎 Paket", callback_data="menu_paket"),
        ],
        [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
    ])
    return InlineKeyboardMarkup(keyboard)


def recon_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 DNS", callback_data="recon_dns"),
         InlineKeyboardButton("🔎 Subdomain", callback_data="recon_sub")],
        [InlineKeyboardButton("📋 WHOIS", callback_data="recon_whois"),
         InlineKeyboardButton("🌍 IP", callback_data="recon_ip")],
        [InlineKeyboardButton("🔒 SSL", callback_data="recon_ssl"),
         InlineKeyboardButton("🔧 Tech", callback_data="recon_tech")],
        [InlineKeyboardButton("🛡️ WAF", callback_data="recon_waf"),
         InlineKeyboardButton("🔭 Shodan", callback_data="recon_shodan")],
        [InlineKeyboardButton("🕵️ Dork", callback_data="recon_dork"),
         InlineKeyboardButton("📡 AXFR", callback_data="recon_axfr")],
        [InlineKeyboardButton("🔄 Reverse DNS", callback_data="recon_rev")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def vuln_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Full Scan", callback_data="vuln_scan")],
        [InlineKeyboardButton("💉 SQLi", callback_data="vuln_sqli"),
         InlineKeyboardButton("🎯 XSS", callback_data="vuln_xss")],
        [InlineKeyboardButton("📂 LFI", callback_data="vuln_lfi"),
         InlineKeyboardButton("🌐 SSRF", callback_data="vuln_ssrf")],
        [InlineKeyboardButton("🔀 Redirect", callback_data="vuln_redirect"),
         InlineKeyboardButton("🔓 CORS", callback_data="vuln_cors")],
        [InlineKeyboardButton("⚙️ Methods", callback_data="vuln_methods"),
         InlineKeyboardButton("📁 Dir", callback_data="vuln_dir")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def osint_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📱 Phone", callback_data="osint_phone"),
         InlineKeyboardButton("📧 Email", callback_data="osint_email")],
        [InlineKeyboardButton("👤 Username", callback_data="osint_username"),
         InlineKeyboardButton("🌍 IP", callback_data="osint_ip")],
        [InlineKeyboardButton("🆔 NIK", callback_data="osint_nik"),
         InlineKeyboardButton("🏦 Rekening", callback_data="osint_rekening")],
        [InlineKeyboardButton("📸 Instagram", callback_data="osint_instagram"),
         InlineKeyboardButton("💬 Telegram", callback_data="osint_telegram")],
        [InlineKeyboardButton("🎯 PhoneTrack", callback_data="osint_phonetrack"),
         InlineKeyboardButton("📋 Pastebin", callback_data="osint_pastebin")],
        [InlineKeyboardButton("🖼 EXIF", callback_data="osint_exif"),
         InlineKeyboardButton("📜 SubHist", callback_data="osint_subhist")],
        [InlineKeyboardButton("🔭 Shodan-D", callback_data="osint_shodand"),
         InlineKeyboardButton("🚨 LeakCheck", callback_data="osint_leakcheck")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def tools_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔐 Base64 Encode", callback_data="tools_base64e"),
         InlineKeyboardButton("🔓 Base64 Decode", callback_data="tools_base64d")],
        [InlineKeyboardButton("#️⃣ Hash", callback_data="tools_hash"),
         InlineKeyboardButton("🎫 JWT Decode", callback_data="tools_jwt")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def owner_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="owner_adduser"),
         InlineKeyboardButton("➖ Remove", callback_data="owner_removeuser")],
        [InlineKeyboardButton("⏱️ Extend", callback_data="owner_extend"),
         InlineKeyboardButton("🚫 Ban", callback_data="owner_ban")],
        [InlineKeyboardButton("✅ Unban", callback_data="owner_unban"),
         InlineKeyboardButton("📋 List User", callback_data="owner_listuser")],
        [InlineKeyboardButton("🔍 User Info", callback_data="owner_userinfo"),
         InlineKeyboardButton("🔄 Cek Expired", callback_data="owner_cekexpired")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


def paket_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🎁 Trial (FREE)", callback_data="buy_trial"),
         InlineKeyboardButton("🥉 Basic (10rb)", callback_data="buy_basic")],
        [InlineKeyboardButton("🥈 Premium (25rb)", callback_data="buy_premium"),
         InlineKeyboardButton("🥇 Pro (50rb)", callback_data="buy_pro")],
        [InlineKeyboardButton("👑 Lifetime (200rb)", callback_data="buy_lifetime")],
        [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
    ])


# ================== START & USER COMMANDS ==================

async def start(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button())
        return

    user = get_user(uid) if not is_owner_uid(uid) else None
    hari = sisa_hari(uid) if user else 0

    if is_owner_uid(uid):
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
            f"🚦 *Status* : 🟢 `ACTIVE`\n\n"
            "✨ *Pilih menu di bawah:*"
        )

    try:
        await update.message.reply_photo(
            photo=BANNER_URL, caption=caption,
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(uid)
        )
    except Exception as e:
        logger.error(f"Banner error: {e}")
        await update.message.reply_text(caption, parse_mode="Markdown",
                                         reply_markup=main_menu_keyboard(uid))


async def myaccount_cmd(update, context):
    uid = update.effective_user.id
    if is_owner_uid(uid):
        await update.message.reply_text("👑 Kamu owner.")
        return
    if not is_registered(uid):
        await update.message.reply_text("❌ Belum terdaftar.")
        return
    user = get_user(uid)
    hari = sisa_hari(uid)
    await update.message.reply_text(
        f"👤 *AKUN SAYA*\n\n"
        f"🆔 `{user['id']}`\n"
        f"📛 *{user['nama']}*\n"
        f"📦 `{user['paket'].upper()}`\n"
        f"⏳ *{hari} hari*\n"
        f"🚦 `{user['status'].upper()}`",
        parse_mode="Markdown", reply_markup=owner_button()
    )


async def paket_cmd(update, context):
    paket = get_paket_list()
    text = "💎 *DAFTAR PAKET*\n\n"
    emoji_map = {"trial": "🎁", "basic": "🥉", "premium": "🥈",
                 "pro": "🥇", "lifetime": "👑"}
    for nama, info in paket.items():
        harga = "GRATIS" if info["harga"] == 0 else f"Rp {info['harga']:,}".replace(",", ".")
        text += f"{emoji_map.get(nama, '📦')} *{nama.upper()}* — {info['durasi']}h — *{harga}*\n"
    text += f"\n📞 {owner_link()}"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=owner_button())


async def owner_cmd(update, context):
    await update.message.reply_text(
        f"👑 *OWNER INFO*\n\n"
        f"📛 *{NAMA_OWNER}*\n"
        f"💬 @{OWNER_USERNAME}\n"
        f"📌 v{VERSION}",
        parse_mode="Markdown", reply_markup=owner_button()
    )


# ================== CALLBACK ==================

async def menu_callback(update, context):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id

    if not is_owner_uid(uid):
        status, pesan = cek_akses(uid)
        if status in ("unregistered", "banned", "expired"):
            await safe_edit(query, pesan, owner_button())
            return

    user = get_user(uid) if not is_owner_uid(uid) else None
    hari = sisa_hari(uid) if user else 0

    def header(title, emoji="✨"):
        return f"╔══════════════════════╗\n║  {emoji} *{title}*\n╚══════════════════════╝\n\n"

    if data == "menu_main":
        if is_owner_uid(uid):
            caption = (
                header("OWNER ACCESS", "👑") +
                f"👑 *{NAMA_OWNER}*\n"
                f"📡 🟢 `ONLINE`\n"
                f"👥 `{user_count()}`\n"
                f"🔧 `v{VERSION}`\n\n"
                "✨ *Pilih menu:*"
            )
        else:
            caption = (
                header("DIABLOX HUNT", "🛡️") +
                f"👋 Halo, *{user['nama']}*!\n\n"
                f"📦 `{user['paket'].upper()}`\n"
                f"⏰ `{hari} hari`\n"
                f"🚦 🟢 `ACTIVE`\n\n"
                "✨ *Pilih menu:*"
            )
        await safe_edit(query, caption, main_menu_keyboard(uid))
        return

    if data == "menu_recon":
        await safe_edit(query,
            header("RECON TOOLS", "🔍") +
            "🌐 DNS  🔎 Subdomain\n📋 WHOIS  🌍 IP\n"
            "🔒 SSL  🔧 Tech\n🛡️ WAF  🔭 Shodan\n"
            "🕵️ Dork  📡 AXFR\n🔄 Reverse DNS",
            recon_menu_keyboard())
        return

    if data == "menu_vuln":
        if not is_owner_uid(uid) and user and user["fitur"] == "recon":
            await query.answer("🔒 Paket BASIC hanya Recon!", show_alert=True)
            return
        await safe_edit(query,
            header("VULN SCANNER", "💥") +
            "🚀 Full Scan  💉 SQLi  🎯 XSS\n"
            "📂 LFI  🌐 SSRF  🔀 Redirect\n"
            "🔓 CORS  ⚙️ Methods  📁 Dir",
            vuln_menu_keyboard())
        return

    if data == "menu_osint":
        ok, msg = cek_akses_osint(uid)
        if not ok:
            await safe_edit(query, msg, owner_button())
            return
        await safe_edit(query,
            header("OSINT TOOLS", "🕵️") +
            "📱 Phone  📧 Email\n"
            "👤 Username  🌍 IP\n"
            "🆔 NIK  🏦 Rekening\n"
            "📸 Instagram  💬 Telegram\n"
            "🎯 PhoneTrack  📋 Pastebin\n"
            "🖼 EXIF  📜 SubHist\n"
            "🔭 Shodan-D  🚨 LeakCheck\n\n"
            "🔒 _Khusus paket PRO / LIFETIME_",
            osint_menu_keyboard())
        return

    if data == "menu_tools":
        await safe_edit(query,
            header("TOOLS", "🧰") +
            "🔐 Base64 Encode  🔓 Base64 Decode\n"
            "#️⃣ Hash  🎫 JWT Decode",
            tools_menu_keyboard())
        return

    if data == "menu_owner":
        if not is_owner_uid(uid):
            await query.answer("❌ Owner only!", show_alert=True)
            return
        await safe_edit(query,
            header("OWNER PANEL", "👑") +
            f"📊 Total User: `{user_count()}`\n\n"
            "➕ Add  ➖ Remove  ⏱️ Extend\n"
            "🚫 Ban  ✅ Unban  📋 List\n"
            "🔍 Info  🔄 Cek Expired",
            owner_menu_keyboard())
        return

    if data == "menu_akun":
        if is_owner_uid(uid):
            await query.answer("👑 Kamu owner!", show_alert=True)
            return
        await safe_edit(query,
            header("AKUN SAYA", "👤") +
            f"🆔 `{user['id']}`\n"
            f"📛 *{user['nama']}*\n"
            f"📦 `{user['paket'].upper()}`\n"
            f"⏳ *{hari} hari*\n"
            f"🚦 `{user['status'].upper()}`",
            InlineKeyboardMarkup([
                [InlineKeyboardButton("🎁 My Referral", callback_data="menu_myref")],
                [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
            ]))
        return

    if data == "menu_myref":
        stats = get_ref_stats(uid) or {"code": "-", "count": 0, "history": []}
        await safe_edit(query,
            header("REFERRAL", "🎁") +
            f"🎫 `{stats['code']}`\n\n"
            f"📊 Total: *{stats['count']}*\n"
            f"🎁 Bonus: *+7 hari*",
            InlineKeyboardMarkup([
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
            caption += f"{emoji_map.get(nama, '📦')} *{nama.upper()}* — {info['durasi']}h — *{harga}*\n"
        caption += "\n💬 _Klik tombol untuk beli_"
        await safe_edit(query, caption, paket_keyboard())
        return

    prompts = {
        # RECON
        "recon_dns": "🌐 `/dns example.com`",
        "recon_sub": "🔎 `/sub example.com`",
        "recon_whois": "📋 `/whois example.com`",
        "recon_ip": "🌍 `/ip 8.8.8.8`",
        "recon_ssl": "🔒 `/ssl example.com`",
        "recon_tech": "🔧 `/tech https://example.com`",
        "recon_waf": "🛡️ `/waf https://example.com`",
        "recon_shodan": "🔭 `/shodan 8.8.8.8`",
        "recon_dork": "🕵️ `/dork example.com`",
        "recon_axfr": "📡 `/axfr example.com`",
        "recon_rev": "🔄 `/rev 8.8.8.8`",
        # VULN
        "vuln_scan": "🚀 `/scan example.com`",
        "vuln_sqli": "💉 `/sqli <url>`",
        "vuln_xss": "🎯 `/xss <url>`",
        "vuln_lfi": "📂 `/lfi <url>`",
        "vuln_ssrf": "🌐 `/ssrf <url>`",
        "vuln_redirect": "🔀 `/redirect <url>`",
        "vuln_cors": "🔓 `/cors <url>`",
        "vuln_methods": "⚙️ `/methods <url>`",
        "vuln_dir": "📁 `/dir <url>`",
        # TOOLS
        "tools_base64e": "🔐 `/base64e hello`",
        "tools_base64d": "🔓 `/base64d aGVsbG8=`",
        "tools_hash": "#️⃣ `/hash hello`",
        "tools_jwt": "🎫 `/jwt <token>`",
        # OSINT
        "osint_phone": "📱 `/phone 628123456789`",
        "osint_email": "📧 `/email target@gmail.com`",
        "osint_username": "👤 `/username johndoe`",
        "osint_ip": "🌍 `/ipinfo 8.8.8.8`",
        "osint_nik": "🆔 `/nik 3201234567890001`",
        "osint_rekening": "🏦 `/rek 1234567890`",
        "osint_instagram": "📸 `/ig johndoe`",
        "osint_telegram": "💬 `/tg johndoe`",
        "osint_phonetrack": "🎯 `/phonetrack 628123456789`",
        "osint_pastebin":   "📋 `/pastebin example.com`",
        "osint_exif":       "🖼 `/exif https://i.imgur.com/xxx.jpg`",
        "osint_subhist":    "📜 `/subhist example.com`",
        "osint_shodand":    "🔭 `/shodand example.com`",
        "osint_leakcheck":  "🚨 `/leakcheck email@example.com`",
        # OWNER
        "owner_adduser": "➕ `/adduser <id> <nama> <paket>`",
        "owner_removeuser": "➖ `/removeuser <id>`",
        "owner_extend": "⏱️ `/extend <id> <hari>`",
        "owner_ban": "🚫 `/ban <id>`",
        "owner_unban": "✅ `/unban <id>`",
        "owner_listuser": "📋 `/listuser`",
        "owner_userinfo": "🔍 `/userinfo <id>`",
        "owner_cekexpired": "🔄 `/cekexpired`",
    }

    if data in prompts:
        await safe_edit(query,
            f"📝 *PROMPT*\n\n{prompts[data]}\n\n_Ketik perintah di chat._",
            InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_main")],
            ]))
        return

    if data.startswith("buy_"):
        paket_nama = data.replace("buy_", "")
        paket = get_paket_list().get(paket_nama, {})
        harga = "GRATIS" if paket.get("harga") == 0 else f"Rp {paket.get('harga', 0):,}".replace(",", ".")
        await safe_edit(query,
            header("BELI PAKET", "💎") +
            f"📦 *{paket_nama.upper()}*\n"
            f"💰 *{harga}*\n\n"
            f"📞 {owner_link()}",
            InlineKeyboardMarkup([
                [InlineKeyboardButton(f"💬 Chat Owner @{OWNER_USERNAME}", url=f"https://t.me/{OWNER_USERNAME}")],
                [InlineKeyboardButton("⬅️ Kembali", callback_data="menu_paket")],
            ]))
        return


# ================== OWNER CMD ==================

async def adduser_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if len(context.args) < 3:
        await update.message.reply_text("❌ `/adduser <id> <nama> <paket>`", parse_mode="Markdown"); return
    try: target_id = int(context.args[0])
    except: await update.message.reply_text("❌ ID angka"); return
    ok, msg = add_user(target_id, context.args[1], context.args[2].lower())
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def removeuser_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if not context.args: await update.message.reply_text("❌ `/removeuser <id>`", parse_mode="Markdown"); return
    try: target_id = int(context.args[0])
    except: return
    ok, msg = remove_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def extend_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if len(context.args) < 2: await update.message.reply_text("❌ `/extend <id> <hari>`", parse_mode="Markdown"); return
    try: target_id = int(context.args[0]); hari = int(context.args[1])
    except: return
    ok, msg = extend_user(target_id, hari)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def ban_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if not context.args: return
    try: target_id = int(context.args[0])
    except: return
    ok, msg = ban_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def unban_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if not context.args: return
    try: target_id = int(context.args[0])
    except: return
    ok, msg = unban_user(target_id)
    await update.message.reply_text(f"{'✅' if ok else '❌'} {msg}")


async def listuser_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return   
    users = list_users()
    if not users: await update.message.reply_text("📭 Kosong"); return
    text = "👥 *USER LIST*\n\n"
    for id_str, u in users.items():
        hari = sisa_hari(int(id_str))
        emoji = "🚫" if u["status"] == "banned" else ("🟢" if hari > 0 else "🔴")
        text += f"{emoji} *{u['nama']}* — {u['paket']} — {hari}h — `{id_str}`\n"
    if len(text) > 4000: text = text[:4000] + "..."
    await update.message.reply_text(text, parse_mode="Markdown")


async def userinfo_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    if not context.args: return
    try: target_id = int(context.args[0])
    except: return
    user = get_user(target_id)
    if not user: await update.message.reply_text("❌ Gak ada"); return
    hari = sisa_hari(target_id)
    await update.message.reply_text(
        f"👤 *{user['nama']}*\n"
        f"🆔 `{target_id}`\n"
        f"📦 `{user['paket'].upper()}`\n"
        f"⏳ *{hari} hari*\n"
        f"🚦 `{user['status'].upper()}`",
        parse_mode="Markdown")


async def setowner_cmd(update, context):
    uid = update.effective_user.id
    if get_owner_id() != 0 and not is_owner_uid(uid): return
    if not context.args: return
    try: new_owner = int(context.args[0])
    except: return
    set_owner_id(new_owner)
    await update.message.reply_text(f"✅ Owner baru: `{new_owner}`", parse_mode="Markdown")


# ================== REFERRAL ==================

async def myref_cmd(update, context):
    uid = update.effective_user.id
    if is_owner_uid(uid):
        stats = get_ref_stats(uid) or {"code": "-", "count": 0, "history": []}
    else:
        status, pesan = cek_akses(uid)
        if status in ("unregistered", "banned", "expired"):
            await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
        stats = get_ref_stats(uid)
        if not stats: return
    await update.message.reply_text(
        f"🎁 *REFERRAL*\n\n🎫 `{stats['code']}`\n📊 Total: *{stats['count']}*",
        parse_mode="Markdown", reply_markup=owner_button())


async def topref_cmd(update, context):
    top = get_top_referrers(10)
    if not top: await update.message.reply_text("📭 Kosong"); return
    text = "🏆 *TOP REFERRERS*\n\n"
    for i, (_, user) in enumerate(top, 1):
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f" {i}."
        text += f"{medal} *{user['nama']}* — {user['ref_count']} ref\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def register_cmd(update, context):
    uid = update.effective_user.id
    if is_owner_uid(uid):
        await update.message.reply_text("👑 Kamu owner."); return
    if is_registered(uid):
        await update.message.reply_text("✅ Sudah terdaftar."); return
    if not context.args:
        await update.message.reply_text("❌ `/register <nama> [kode_ref]`", parse_mode="Markdown"); return
    nama = context.args[0]
    ref_code = context.args[1] if len(context.args) > 1 else None
    referred_by = get_ref_by_code(ref_code) if ref_code else None
    ok, msg = add_user(uid, nama, "trial", hari=0, referred_by=referred_by)
    if ok:
        await update.message.reply_text(f"✅ Terdaftar sebagai *{nama}*", parse_mode="Markdown", reply_markup=owner_button())
    else:
        await update.message.reply_text(f"❌ {msg}")


# ================== NOTIF EXPIRED ==================

async def cek_expired_job(context):
    try:
        for uid, user in get_users_expiring(3):
            if is_notified(uid, "h3"): continue
            try:
                await context.bot.send_message(int(uid), f"⏰ *{user['nama']}*, expired 3 hari lagi. {owner_link()}", parse_mode="Markdown", reply_markup=owner_button())
                mark_notified(uid, "h3")
            except: pass
        for uid, user in get_users_expiring(1):
            if is_notified(uid, "h1"): continue
            try:
                await context.bot.send_message(int(uid), f"⚠️ *{user['nama']}*, expired BESOK.", parse_mode="Markdown", reply_markup=owner_button())
                mark_notified(uid, "h1")
            except: pass
        for uid, user in get_users_expired_today():
            if is_notified(uid, "exp"): continue
            try:
                await context.bot.send_message(int(uid), f"🔴 *{user['nama']}*, sudah EXPIRED.", parse_mode="Markdown", reply_markup=owner_button())
                mark_notified(uid, "exp")
            except: pass
    except Exception as e:
        logger.error(f"cek_expired_job: {e}")


async def cekexpired_cmd(update, context):
    uid = update.effective_user.id
    if not is_owner_uid(uid): return
    msg = await update.message.reply_text("🔄 Cek...")
    await cek_expired_job(context)
    await msg.edit_text("✅ Selesai.")


# ================== RECON ==================

async def dns_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain or not is_valid_domain(domain):
        await update.message.reply_text("❌ `/dns example.com`", parse_mode="Markdown"); return
    msg = await update.message.reply_text(f"🔍 DNS `{domain}`...")
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
        await msg.edit_text(f"❌ {e}")


async def sub_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain: await update.message.reply_text("❌ `/sub example.com`", parse_mode="Markdown"); return
    msg = await update.message.reply_text(f"🔍 Subdomain `{domain}`...")
    try:
        subs = await asyncio.to_thread(subdomain_scan, domain)
        if not subs: await msg.edit_text("❌ Kosong"); return
        text = f"🌐 *Subdomains: {domain}* ({len(subs)})\n\n"
        for s in subs[:40]: text += f"• `{s['subdomain']}` → `{s['ip']}`\n"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def whois_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain: return
    msg = await update.message.reply_text(f"🔍 WHOIS `{domain}`...")
    try:
        result = await asyncio.to_thread(whois_lookup, domain)
        if isinstance(result, dict) and "error" in result:
            await msg.edit_text(f"❌ {result['error']}"); return
        await msg.edit_text(f"📋 *WHOIS: {domain}*\n\n`{result[:3500]}`", parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def ip_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    target = get_arg(context)
    if not target: return
    try:
        ip = target if target.replace(".", "").isdigit() else await asyncio.to_thread(resolve_domain, target)
        if not ip: await update.message.reply_text("❌ Gagal resolve"); return
        msg = await update.message.reply_text(f"🔍 IP `{ip}`...")
        info = await asyncio.to_thread(ip_info, ip)
        if "error" in info: await msg.edit_text(f"❌ {info['error']}"); return
        text = f"🌍 *IP: {info['IP']}*\n\n"
        for k, v in info.items():
            if k != "IP": text += f"*{k}:* `{v}`\n"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


async def ssl_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain: return
    msg = await update.message.reply_text(f"🔍 SSL `{domain}`...")
    try:
        info = await asyncio.to_thread(ssl_info, domain)
        if "error" in info: await msg.edit_text(f"❌ {info['error']}"); return
        text = f"🔒 *SSL: {domain}*\n\n"
        for k, v in info.items(): text += f"*{k}:* `{v}`\n"
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def tech_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    url = get_arg(context)
    if not url: return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Tech `{url}`...")
    try:
        tech = await asyncio.to_thread(tech_detect, url)
        text = f"🔧 *Tech: {url}*\n\n"
        if tech:
            for t in tech: text += f"• `{t}`\n"
        else: text += "_Kosong_"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def waf_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    url = get_arg(context)
    if not url: return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 WAF `{url}`...")
    try:
        wafs = await asyncio.to_thread(waf_detect, url)
        text = f"🛡️ *WAF: {url}*\n\n"
        if wafs:
            for w in wafs: text += f"• `{w}`\n"
        else: text += "_Kosong_"
        await msg.edit_text(text, parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def shodan_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    ip = get_arg(context)
    if not ip or not SHODAN_KEY: return
    msg = await update.message.reply_text(f"🔍 Shodan `{ip}`...")
    try:
        info = await asyncio.to_thread(shodan_lookup, ip, SHODAN_KEY)
        if "error" in info: await msg.edit_text(f"❌ {info['error']}"); return
        await msg.edit_text(f"🔎 *Shodan: {info['IP']}*\n\nOrg: `{info.get('Org')}`\nPorts: `{info.get('Ports')}`", parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def dork_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain: return
    dorks = dork_search(domain)
    text = f"🔍 *Dorks: {domain}*\n\n"
    for d in dorks: text += f"`{d}`\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def axfr_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    domain = get_arg(context)
    if not domain: return
    msg = await update.message.reply_text(f"🔍 AXFR `{domain}`...")
    try:
        records = await asyncio.to_thread(zone_transfer, domain)
        if records:
            text = "⚠️ *ZONE TRANSFER BERHASIL!*\n\n"
            for r in records[:50]: text += f"`{r}`\n"
            await msg.edit_text(text, parse_mode="Markdown")
        else:
            await msg.edit_text("✅ Gagal (dilindungi)")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def rev_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    ip = get_arg(context)
    if not ip: return
    try:
        result = await asyncio.to_thread(reverse_dns, ip)
        if result:
            await update.message.reply_text(f"🔍 *Rev DNS {ip}:*\n\n`{result}`", parse_mode="Markdown")
        else:
            await update.message.reply_text(f"❌ Tidak ada PTR untuk `{ip}`")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


# ================== VULN ==================

async def scan_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    if not is_owner_uid(uid):
        user = get_user(uid)
        if user and user["fitur"] == "recon":
            await update.message.reply_text("🔒 Basic hanya Recon.", reply_markup=owner_button()); return
    target = get_arg(context)
    if not target: await update.message.reply_text("❌ `/scan example.com`", parse_mode="Markdown"); return
    url = normalize_url(target)
    domain = urlparse(url).hostname
    if not is_valid_domain(domain) or not resolve_domain(domain):
        await update.message.reply_text("❌ Domain invalid"); return
    msg = await update.message.reply_text(f"🔍 Scan `{domain}`... (1-3 mnt)")
    try:
        scanner = VulnScanner(target)
        result = await asyncio.to_thread(scanner.run)
    except Exception as e:
        await msg.edit_text(f"❌ {e}"); return
    if "error" in result: await msg.edit_text(f"❌ {result['error']}"); return
    findings = result["findings"]
    text = f"✅ *SCAN SELESAI*\n\n🌐 `{result['domain']}`\n📡 `{result['ip']}`\n⏰ `{result['time']}`\n\n"
    if findings:
        text += summary_text(findings) + "\n" + fmt_findings(findings, 10)
    else:
        text += "✅ _Tidak ada kerentanan_"
    if len(text) > 4000: text = text[:4000] + "\n..."
    await msg.edit_text(text, parse_mode="Markdown")
    try:
        json_file = save_json_report(result); html_file = save_html_report(result)
        with open(json_file, "rb") as f:
            await update.message.reply_document(document=f, filename=os.path.basename(json_file), caption=f"📄 JSON - {result['domain']}")
        with open(html_file, "rb") as f:
            await update.message.reply_document(document=f, filename=os.path.basename(html_file), caption=f"🌐 HTML - {result['domain']}")
    except Exception as e:
        logger.error(f"Report: {e}")


async def _quick_vuln(update, context, test_name, test_func):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    if not is_owner_uid(uid):
        user = get_user(uid)
        if user and user["fitur"] == "recon":
            await update.message.reply_text("🔒 Basic hanya Recon."); return
    url = get_arg(context)
    if not url: await update.message.reply_text(f"❌ `/{test_name} <url>`", parse_mode="Markdown"); return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Test {test_name} `{url}`...")
    try:
        scanner = VulnScanner(url)
        await asyncio.to_thread(scanner.crawl, url, 1)
        if not scanner.params: await msg.edit_text("❌ Gak ada parameter"); return
        await asyncio.to_thread(test_func, scanner)
        if not scanner.findings: await msg.edit_text(f"✅ Gak ada {test_name}"); return
        text = f"⚠️ *{test_name.upper()} DITEMUKAN!*\n\n" + fmt_findings(scanner.findings, 10)
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


async def sqli_cmd(update, context): await _quick_vuln(update, context, "sqli", lambda s: s.test_sqli())
async def xss_cmd(update, context): await _quick_vuln(update, context, "xss", lambda s: s.test_xss())
async def lfi_cmd(update, context): await _quick_vuln(update, context, "lfi", lambda s: s.test_lfi())
async def ssrf_cmd(update, context): await _quick_vuln(update, context, "ssrf", lambda s: s.test_ssrf())
async def redirect_cmd(update, context): await _quick_vuln(update, context, "open redirect", lambda s: s.test_open_redirect())
async def methods_cmd(update, context): await _quick_vuln(update, context, "http methods", lambda s: s.test_http_methods())


async def cors_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    url = get_arg(context)
    if not url: return
    url = normalize_url(url)
    try:
        results = await asyncio.to_thread(cors_check, url)
        if not results: await update.message.reply_text("✅ Gak ada misconfig"); return
        text = "⚠️ *CORS Misconfig!*\n\n"
        for r in results: text += f"• `{r['severity']}` — `{r['acao']}`\n"
        await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


async def dir_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    url = get_arg(context)
    if not url: return
    url = normalize_url(url)
    msg = await update.message.reply_text(f"🔍 Dir `{url}`...")
    try:
        scanner = VulnScanner(url)
        await asyncio.to_thread(scanner.dir_bruteforce)
        if not scanner.findings: await msg.edit_text("✅ Gak ada directory"); return
        text = "📁 *Directories:*\n\n" + fmt_findings(scanner.findings, 30)
        await msg.edit_text(text[:4000], parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"❌ {e}")


# ================== OSINT ==================

async def _osint_run(update, context, fn, label, usage):
    uid = update.effective_user.id
    ok, msg = cek_akses_osint(uid)
    if not ok:
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=owner_button())
        return
    arg = " ".join(context.args) if context.args else ""
    if not arg:
        await update.message.reply_text(f"❌ Usage: `{usage}`", parse_mode="Markdown")
        return
    m = await update.message.reply_text(f"🔍 {label} `{arg}`...")
    try:
        result = await asyncio.to_thread(fn, arg)
    except Exception as e:
        result = f"❌ Error: {e}"
    if len(result) > 4000:
        result = result[:4000] + "\n..."
    try:
        await m.edit_text(result, parse_mode="Markdown")
    except Exception:
        await m.edit_text(result)


async def _osint_run_async(update, context, afn, label, usage):
    """Untuk fungsi async (mis. scan_rekening versi baru)."""
    uid = update.effective_user.id
    ok, msg = cek_akses_osint(uid)
    if not ok:
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=owner_button())
        return
    arg = " ".join(context.args) if context.args else ""
    if not arg:
        await update.message.reply_text(f"❌ Usage: `{usage}`", parse_mode="Markdown")
        return
    m = await update.message.reply_text(f"🔍 {label} `{arg}`...")
    try:
        result = await afn(arg)
    except Exception as e:
        result = f"❌ Error: {e}"
    if len(result) > 4000:
        result = result[:4000] + "\n..."
    try:
        await m.edit_text(result, parse_mode="Markdown")
    except Exception:
        await m.edit_text(result)


async def osint_phone_cmd(u, c):      await _osint_run(u, c, scan_phone,         "Phone",    "/phone 628123456789")
async def osint_email_cmd(u, c):      await _osint_run(u, c, scan_email,         "Email",    "/email target@gmail.com")
async def osint_username_cmd(u, c):   await _osint_run(u, c, scan_username,      "Username", "/username johndoe")
async def osint_ip_cmd(u, c):         await _osint_run(u, c, scan_ip,            "IP",       "/ipinfo 8.8.8.8")
async def osint_nik_cmd(u, c):        await _osint_run(u, c, scan_nik,           "NIK",      "/nik 3201234567890001")
async def osint_rek_cmd(u, c):        await _osint_run(u, c, scan_rekening,      "Rekening", "/rek 1234567890")
async def osint_ig_cmd(u, c):         await _osint_run(u, c, scan_ig,            "Instagram","/ig johndoe")
async def osint_tg_cmd(u, c):         await _osint_run(u, c, scan_telegram,      "Telegram", "/tg johndoe")

# --- EXTRA OSINT ---
async def osint_phonetrack_cmd(u, c): await _osint_run_async(u, c, scan_phonetrack,        "PhoneTrack", "/phonetrack 628123456789")
async def osint_pastebin_cmd(u, c):   await _osint_run_async(u, c, scan_pastebin,          "Pastebin",   "/pastebin example.com")
async def osint_exif_cmd(u, c):       await _osint_run_async(u, c, scan_exif,              "EXIF",       "/exif https://i.imgur.com/x.jpg")
async def osint_subhist_cmd(u, c):    await _osint_run_async(u, c, scan_subdomain_history, "SubHist",    "/subhist example.com")
async def osint_shodand_cmd(u, c):    await _osint_run_async(u, c, scan_shodan_domain,     "Shodan-D",   "/shodand example.com")
async def osint_leak_cmd(u, c):       await _osint_run_async(u, c, scan_leakcheck,         "LeakCheck",  "/leakcheck email@example.com")


# ================== TOOLS ==================

async def base64e_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    text = " ".join(context.args) if context.args else ""
    if not text: return
    await update.message.reply_text(f"```\n{base64_encode(text)}\n```", parse_mode="Markdown")


async def base64d_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    text = " ".join(context.args) if context.args else ""
    if not text: return
    try:
        await update.message.reply_text(f"```\n{base64_decode(text)}\n```", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


async def hash_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    text = " ".join(context.args) if context.args else ""
    if not text: return
    await update.message.reply_text(
        f"*MD5:* `{hash_string(text, 'md5')}`\n"
        f"*SHA1:* `{hash_string(text, 'sha1')}`\n"
        f"*SHA256:* `{hash_string(text, 'sha256')}`",
        parse_mode="Markdown")


async def jwt_cmd(update, context):
    uid = update.effective_user.id
    status, pesan = cek_akses(uid)
    if status in ("unregistered", "banned", "expired"):
        await update.message.reply_text(pesan, parse_mode="Markdown", reply_markup=owner_button()); return
    token = get_arg(context)
    if not token: return
    parts = token.split(".")
    if len(parts) != 3: await update.message.reply_text("❌ Bukan JWT"); return
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4)))
        text = f"*Header:*\n```\n{json.dumps(header, indent=2)}\n```\n*Payload:*\n```\n{json.dumps(payload, indent=2)}\n```"
        await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


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
        print("❌ BOT_TOKEN belum di-set"); return
    app = Application.builder().token(BOT_TOKEN).build()

    # Info
    app.add_handler(CommandHandler("start", start))
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
    # OSINT
    app.add_handler(CommandHandler("phone", osint_phone_cmd))
    app.add_handler(CommandHandler("email", osint_email_cmd))
    app.add_handler(CommandHandler("username", osint_username_cmd))
    app.add_handler(CommandHandler("ipinfo", osint_ip_cmd))
    app.add_handler(CommandHandler("nik", osint_nik_cmd))
    app.add_handler(CommandHandler("rek", osint_rek_cmd))
    app.add_handler(CommandHandler("ig", osint_ig_cmd))
    app.add_handler(CommandHandler("tg", osint_tg_cmd))
    # OSINT EXTRA
    app.add_handler(CommandHandler("phonetrack", osint_phonetrack_cmd))
    app.add_handler(CommandHandler("pastebin", osint_pastebin_cmd))
    app.add_handler(CommandHandler("exif", osint_exif_cmd))
    app.add_handler(CommandHandler("subhist", osint_subhist_cmd))
    app.add_handler(CommandHandler("shodand", osint_shodand_cmd))
    app.add_handler(CommandHandler("leakcheck", osint_leak_cmd))
    # Tools
    app.add_handler(CommandHandler("base64e", base64e_cmd))
    app.add_handler(CommandHandler("base64d", base64d_cmd))
    app.add_handler(CommandHandler("hash", hash_cmd))
    app.add_handler(CommandHandler("jwt", jwt_cmd))
    # Callback & text
    app.add_handler(CallbackQueryHandler(menu_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    try:
        jq = app.job_queue
        jq.run_daily(cek_expired_job, time=dt_mod.time(hour=9, minute=0))
        logger.info("Job queue: expired 09:00")
    except Exception as e:
        logger.error(f"JobQueue: {e}")

    print("DiabloXhunt Private Edition running...")
    print(f"Owner ID: {OWNER_ID}")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
