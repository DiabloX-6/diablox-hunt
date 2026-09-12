import json
import os
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
        }
        save_db(default)
        return default
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_owner_id():
    db = load_db()
    return db.get("owner_id", 0)


def set_owner_id(uid):
    db = load_db()
    db["owner_id"] = uid
    save_db(db)


def is_owner(uid):
    return uid == get_owner_id()


def get_user(uid):
    db = load_db()
    return db["users"].get(str(uid))


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


def add_user(uid, nama, paket="trial", hari=None):
    db = load_db()
    if paket not in db["paket"]:
        return False, "Paket tidak valid"
    durasi = hari if hari else db["paket"][paket]["durasi"]
    expired = (datetime.now() + timedelta(days=durasi)).strftime("%Y-%m-%d")
    db["users"][str(uid)] = {
        "id": uid,
        "nama": nama,
        "paket": paket,
        "fitur": db["paket"][paket]["fitur"],
        "start": datetime.now().strftime("%Y-%m-%d"),
        "expired": expired,
        "status": "active",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_db(db)
    return True, f"User {nama} ditambahkan. Expired: {expired}"


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
    return True, f"User dibanned"


def unban_user(uid):
    db = load_db()
    if str(uid) not in db["users"]:
        return False, "User tidak ditemukan"
    db["users"][str(uid)]["status"] = "active"
    save_db(db)
    return True, f"User di-unban"


def list_users():
    db = load_db()
    return db["users"]


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
