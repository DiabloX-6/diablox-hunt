import json
import os
import random
import string
from datetime import datetime, timedelta

DB_FILE = "users.json"


def load_db():
    if not os.path.exists(DB_FILE):
        default = {
            "owner_id": 0,
            "paket": {
                "trial": {"durasi": 3, "harga": 0, "fitur": "all"},
                "basic": {"durasi": 30, "harga": 10000, "fitur": "recon"},
                "premium": {"durasi": 30, "harga": 25000, "fitur": "all"},
                "pro": {"durasi": 30, "harga": 50000, "fitur": "all_unlimited"},
                "lifetime": {"durasi": 36500, "harga": 200000, "fitur": "all_unlimited"},
            },
            "users": {},
            "referrals": {},
            "notified": {},
        }
        save_db(default)
        return default
    with open(DB_FILE, "r") as f:
        data = json.load(f)
    if "referrals" not in data:
        data["referrals"] = {}
    if "notified" not in data:
        data["notified"] = {}
    return data


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_owner_id():
    return load_db().get("owner_id", 0)


def set_owner_id(uid):
    db = load_db()
    db["owner_id"] = uid
    save_db(db)


def is_owner(uid):
    return uid == get_owner_id()


def get_user(uid):
    return load_db()["users"].get(str(uid))


def is_registered(uid):
    return str(uid) in load_db()["users"]


def is_active(uid):
    user = get_user(uid)
    if not user:
        return False
    if user.get("status") != "active":
        return False
    try:
        expired = datetime.strptime(user["expired"], "%Y-%m-%d")
        return expired >= datetime.now()
    except:
        return False


def generate_ref_code(uid):
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"DX{uid}{random_str}"[:12]


def add_user(uid, nama, paket="trial", hari=None, referred_by=None):
    db = load_db()
    if paket not in db["paket"]:
        return False, "Paket tidak valid"
    durasi = hari if hari else db["paket"][paket]["durasi"]

    bonus = 0
    if referred_by and str(referred_by) in db["users"]:
        bonus = 3
    durasi += bonus

    expired = (datetime.now() + timedelta(days=durasi)).strftime("%Y-%m-%d")
    ref_code = generate_ref_code(uid)

    db["users"][str(uid)] = {
        "id": uid,
        "nama": nama,
        "paket": paket,
        "fitur": db["paket"][paket]["fitur"],
        "start": datetime.now().strftime("%Y-%m-%d"),
        "expired": expired,
        "status": "active",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ref_code": ref_code,
        "referred_by": str(referred_by) if referred_by else None,
        "ref_count": 0,
    }

    if referred_by and str(referred_by) in db["users"]:
        ref_uid = str(referred_by)
        try:
            ref_expired = datetime.strptime(db["users"][ref_uid]["expired"], "%Y-%m-%d")
        except:
            ref_expired = datetime.now()
        new_expired = (ref_expired + timedelta(days=7)).strftime("%Y-%m-%d")
        db["users"][ref_uid]["expired"] = new_expired
        db["users"][ref_uid]["ref_count"] = db["users"][ref_uid].get("ref_count", 0) + 1

        if ref_uid not in db["referrals"]:
            db["referrals"][ref_uid] = []
        db["referrals"][ref_uid].append({
            "user_id": str(uid),
            "nama": nama,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reward": 7,
        })

    save_db(db)
    msg = f"User {nama} ditambahkan. Expired: {expired}"
    if bonus:
        msg += f" (+{bonus} hari bonus referral)"
    return True, msg


def remove_user(uid):
    db = load_db()
    if str(uid) not in db["users"]:
        return False, "User tidak ditemukan"
    nama = db["users"][str(uid)]["nama"]
    del db["users"][str(uid)]
    save_db(db)
    return True, f"User {nama} dihapus"


def extend_user(uid, hari):
    db = load_db()
    if str(uid) not in db["users"]:
        return False, "User tidak ditemukan"
    try:
        expired = datetime.strptime(db["users"][str(uid)]["expired"], "%Y-%m-%d")
    except:
        expired = datetime.now()
    new_expired = (expired + timedelta(days=hari)).strftime("%Y-%m-%d")
    db["users"][str(uid)]["expired"] = new_expired
    db["users"][str(uid)]["status"] = "active"
    save_db(db)
    return True, f"Expired baru: {new_expired}"


def ban_user(uid):
    db = load_db()
    if str(uid) not in db["users"]:
        return False, "User tidak ditemukan"
    db["users"][str(uid)]["status"] = "banned"
    save_db(db)
    return True, "User dibanned"


def unban_user(uid):
    db = load_db()
    if str(uid) not in db["users"]:
        return False, "User tidak ditemukan"
    db["users"][str(uid)]["status"] = "active"
    save_db(db)
    return True, "User di-unban"


def list_users():
    return load_db()["users"]


def sisa_hari(uid):
    user = get_user(uid)
    if not user:
        return 0
    try:
        expired = datetime.strptime(user["expired"], "%Y-%m-%d")
        delta = (expired - datetime.now()).days
        return max(0, delta)
    except:
        return 0


def get_paket_list():
    return load_db()["paket"]


def user_count():
    return len(load_db()["users"])


# ================== REFERRAL ==================

def get_ref_code(uid):
    user = get_user(uid)
    if user:
        return user.get("ref_code")
    return None


def get_ref_by_code(code):
    users = load_db()["users"]
    for uid, user in users.items():
        if user.get("ref_code") == code:
            return uid
    return None


def get_ref_stats(uid):
    db = load_db()
    user = get_user(uid)
    if not user:
        return None
    return {
        "code": user.get("ref_code"),
        "count": user.get("ref_count", 0),
        "history": db["referrals"].get(str(uid), []),
    }


def get_top_referrers(limit=10):
    users = load_db()["users"]
    sorted_users = sorted(users.items(), key=lambda x: x[1].get("ref_count", 0), reverse=True)
    return [(uid, u) for uid, u in sorted_users[:limit] if u.get("ref_count", 0) > 0]


# ================== NOTIFIKASI EXPIRED ==================

def get_users_expiring(days_before):
    db = load_db()
    result = []
    today = datetime.now().date()
    target_date = today + timedelta(days=days_before)
    for uid, user in db["users"].items():
        if user.get("status") != "active":
            continue
        try:
            expired = datetime.strptime(user["expired"], "%Y-%m-%d").date()
            if expired == target_date:
                result.append((uid, user))
        except:
            pass
    return result


def get_users_expired_today():
    db = load_db()
    result = []
    today = datetime.now().date()
    for uid, user in db["users"].items():
        try:
            expired = datetime.strptime(user["expired"], "%Y-%m-%d").date()
            if expired == today and user.get("status") == "active":
                result.append((uid, user))
        except:
            pass
    return result


def mark_notified(uid, tipe):
    db = load_db()
    key = f"{uid}_{tipe}_{datetime.now().strftime('%Y%m%d')}"
    db["notified"][key] = True
    save_db(db)


def is_notified(uid, tipe):
    db = load_db()
    key = f"{uid}_{tipe}_{datetime.now().strftime('%Y%m%d')}"
    return db["notified"].get(key, False)
