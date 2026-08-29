from datetime import datetime
from flask import request
from .db import get_db, now

TYPE_LABELS = {
    "revenue": "إيراد",
    "deposit": "توريد",
    "approval": "طلب تصديق",
    "expense": "مصروف",
    "due": "مستحق",
}

TYPE_PREFIX = {
    "revenue": "REV",
    "deposit": "DEP",
    "approval": "APP",
    "expense": "EXP",
    "due": "DUE",
}

STATUS_LABELS = {
    "draft": "مسودة",
    "pending_review": "قيد المراجعة",
    "returned": "مرتجع للتصحيح",
    "approved": "معتمد",
    "rejected": "مرفوض",
    "spent": "مصروف",
    "closed": "مغلق",
}

STATUS_CLASSES = {
    "draft": "status-muted",
    "pending_review": "status-warn",
    "returned": "status-info",
    "approved": "status-ok",
    "rejected": "status-danger",
    "spent": "status-purple",
    "closed": "status-muted",
}


def current_month():
    return datetime.now().strftime("%Y-%m")


def station_for_user(user):
    db = get_db()
    if user["station_id"]:
        return db.execute("SELECT * FROM stations WHERE id=?", (user["station_id"],)).fetchone()
    return db.execute("SELECT * FROM stations ORDER BY id LIMIT 1").fetchone()


def next_operation_number(station_id, op_type):
    db = get_db()
    station = db.execute("SELECT code FROM stations WHERE id=?", (station_id,)).fetchone()
    prefix = TYPE_PREFIX[op_type]
    row = db.execute("SELECT last_no FROM sequences WHERE station_id=? AND doc_type=?", (station_id, prefix)).fetchone()
    if not row:
        db.execute("INSERT INTO sequences(station_id, doc_type, last_no) VALUES(?,?,0)", (station_id, prefix))
        last_no = 0
    else:
        last_no = row["last_no"]
    new_no = last_no + 1
    db.execute("UPDATE sequences SET last_no=? WHERE station_id=? AND doc_type=?", (new_no, station_id, prefix))
    return f"{station['code']}-{prefix}-{new_no:04d}"


def log_action(operation_id, action, old_status=None, new_status=None, note="", user_id=None):
    db = get_db()
    ip = request.remote_addr if request else ""
    db.execute(
        """INSERT INTO operation_actions(operation_id, action, old_status, new_status, note, user_id, ip_address, created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (operation_id, action, old_status, new_status, note, user_id, ip, now()),
    )


def can_review(user):
    return user and user["role"] in ("manager", "super_admin")


def can_create(user):
    return user and user["role"] in ("collector", "manager", "super_admin")


def can_manage_settings(user):
    return user and user["role"] in ("manager", "super_admin")


def can_manage_users(user):
    return user and user["role"] == "super_admin"


def operation_query_scope(user):
    if user["role"] == "super_admin":
        return "1=1", []
    return "o.station_id=?", [user["station_id"]]
