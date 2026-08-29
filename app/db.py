import sqlite3
from datetime import datetime
from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    company_name TEXT NOT NULL,
    manager_name TEXT,
    address TEXT,
    phone TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('super_admin','manager','collector')),
    station_id INTEGER,
    allowed_ip TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    session_token TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(station_id) REFERENCES stations(id)
);

CREATE TABLE IF NOT EXISTS sequences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    doc_type TEXT NOT NULL,
    last_no INTEGER NOT NULL DEFAULT 0,
    UNIQUE(station_id, doc_type),
    FOREIGN KEY(station_id) REFERENCES stations(id)
);

CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    op_no TEXT NOT NULL UNIQUE,
    op_type TEXT NOT NULL CHECK(op_type IN ('revenue','deposit','approval','expense','due')),
    title TEXT NOT NULL,
    category TEXT,
    amount REAL NOT NULL DEFAULT 0,
    allocated_amount REAL,
    description TEXT,
    attachment_path TEXT,
    status TEXT NOT NULL DEFAULT 'pending_review' CHECK(status IN ('draft','pending_review','returned','approved','rejected','spent','closed')),
    locked INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER NOT NULL,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    manager_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(station_id) REFERENCES stations(id),
    FOREIGN KEY(created_by) REFERENCES users(id),
    FOREIGN KEY(reviewed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS operation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id INTEGER,
    action TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    note TEXT,
    user_id INTEGER,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES operations(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    reason TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES operations(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS petty_cash_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    month_key TEXT NOT NULL,
    category TEXT NOT NULL,
    allocated_amount REAL NOT NULL DEFAULT 0,
    spent_amount REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','near_limit','exhausted','closed','due')),
    created_at TEXT NOT NULL,
    UNIQUE(station_id, month_key, category),
    FOREIGN KEY(station_id) REFERENCES stations(id)
);

CREATE TABLE IF NOT EXISTS month_closings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    month_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
    notes TEXT,
    closed_by INTEGER,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(station_id, month_key),
    FOREIGN KEY(station_id) REFERENCES stations(id),
    FOREIGN KEY(closed_by) REFERENCES users(id)
);
"""

DEFAULT_PETTY = [
    ("وقود للمولد", 300000),
    ("إيجار سكن العاملين", 300000),
    ("أدوات مكتبية", 100000),
    ("اتصالات", 10000),
    ("ضيافة", 20000),
    ("إعاشة", 636000),
    ("عاملة نظافة", 80000),
    ("ترحيل عاملين", 80000),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    seed_defaults(db)
    db.commit()


def seed_defaults(db):
    station = db.execute("SELECT id FROM stations WHERE code=?", (current_app.config["DEFAULT_STATION_CODE"],)).fetchone()
    if not station:
        cur = db.execute(
            """INSERT INTO stations(code, name, company_name, manager_name, address, phone, active, created_at)
               VALUES(?,?,?,?,?,?,1,?)""",
            (
                current_app.config["DEFAULT_STATION_CODE"],
                current_app.config["DEFAULT_STATION_NAME"],
                current_app.config["DEFAULT_COMPANY_NAME"],
                current_app.config["DEFAULT_MANAGER_NAME"],
                "دلقو",
                "",
                now(),
            ),
        )
        station_id = cur.lastrowid
    else:
        station_id = station["id"]

    users = [
        ("admin", "admin123", "السوبر أدمن", "super_admin", None),
        ("manager", "manager123", "مدير المحطة", "manager", station_id),
        ("collector", "collector123", "المتحصل المالي", "collector", station_id),
    ]
    for username, password, full_name, role, sid in users:
        exists = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            db.execute(
                """INSERT INTO users(username,password_hash,full_name,role,station_id,allowed_ip,active,created_at)
                   VALUES(?,?,?,?,?,?,1,?)""",
                (username, generate_password_hash(password), full_name, role, sid, "", now()),
            )

    # إنشاء نثرية الشهر الحالي افتراضياً لمحطة دلقو
    month_key = datetime.now().strftime("%Y-%m")
    for category, amount in DEFAULT_PETTY:
        db.execute(
            """INSERT OR IGNORE INTO petty_cash_items(station_id, month_key, category, allocated_amount, spent_amount, status, created_at)
               VALUES(?,?,?,?,0,'active',?)""",
            (station_id, month_key, category, amount, now()),
        )
    db.execute(
        """INSERT OR IGNORE INTO month_closings(station_id, month_key, status, notes, created_at)
           VALUES(?,?, 'open', '', ?)""",
        (station_id, month_key, now()),
    )
