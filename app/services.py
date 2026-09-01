from datetime import datetime
from flask import request
from .db import get_db, now

TYPE_LABELS = {
    "approval": "طلب تصديق",
    "due": "مستحق / سلفة",
}
TYPE_PREFIX = {"approval": "APP", "due": "DUE"}
STATUS_LABELS = {
    "draft": "مسودة",
    "pending_review": "قيد المراجعة",
    "returned": "مرتجع للتصحيح",
    "approved": "معتمد",
    "rejected": "مرفوض",
    "closed": "مسوّى",
}
STATUS_CLASSES = {
    "draft": "status-muted",
    "pending_review": "status-warn",
    "returned": "status-info",
    "approved": "status-ok",
    "rejected": "status-danger",
    "closed": "status-purple",
}
ROLE_LABELS = {"super_admin": "مدير النظام", "manager": "مدير المحطة", "collector": "المتحصل"}


def current_month():
    return datetime.now().strftime("%Y-%m")


def station_for_user(user):
    db = get_db()
    if user["station_id"]:
        return db.execute("SELECT * FROM stations WHERE id=?", (user["station_id"],)).fetchone()
    return None


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
    db.execute(
        """INSERT INTO operation_actions(operation_id, action, old_status, new_status, note, user_id, ip_address, created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (operation_id, action, old_status, new_status, note, user_id, request.remote_addr or "", now()),
    )


def log_event(event_type, description, user_id=None, station_id=None):
    db = get_db()
    db.execute(
        """INSERT INTO audit_events(event_type, description, station_id, user_id, ip_address, created_at)
           VALUES(?,?,?,?,?,?)""",
        (event_type, description, station_id, user_id, request.remote_addr or "", now()),
    )


def operation_query_scope(user):
    if user["role"] == "super_admin":
        return "1=1", []
    return "o.station_id=?", [user["station_id"]]


def petty_totals(station_id, month_key=None):
    month_key = month_key or current_month()
    db = get_db()
    allocation = db.execute(
        "SELECT COALESCE(SUM(allocated_amount),0) total FROM petty_cash_items WHERE station_id=? AND month_key=?",
        (station_id, month_key),
    ).fetchone()["total"]
    spent = db.execute(
        """SELECT COALESCE(SUM(amount),0) total FROM operations
           WHERE station_id=? AND op_type='approval' AND status='approved'
             AND strftime('%Y-%m', created_at)=?""",
        (station_id, month_key),
    ).fetchone()["total"]
    funded = db.execute(
        """SELECT COALESCE(SUM(amount),0) total FROM operations
           WHERE station_id=? AND op_type='due' AND status IN ('approved','closed')
             AND strftime('%Y-%m', created_at)=?""",
        (station_id, month_key),
    ).fetchone()["total"]
    settled = db.execute(
        """SELECT COALESCE(SUM(ds.amount),0) total FROM due_settlements ds
           JOIN operations o ON o.id=ds.operation_id
           WHERE o.station_id=? AND strftime('%Y-%m', o.created_at)=?""",
        (station_id, month_key),
    ).fetchone()["total"]
    received = db.execute(
        """SELECT COALESCE(SUM(amount),0) total FROM petty_cash_receipts
           WHERE station_id=? AND month_key=? AND status='approved'""",
        (station_id, month_key),
    ).fetchone()["total"]
    actual = funded + received - spent - settled
    return {"allocation": allocation, "spent": spent, "funded": funded, "received": received, "settled": settled, "actual": actual}
