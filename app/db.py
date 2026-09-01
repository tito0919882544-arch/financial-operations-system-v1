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
    company_name TEXT NOT NULL DEFAULT '',
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
    op_type TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT,
    amount REAL NOT NULL DEFAULT 0,
    allocated_amount REAL,
    description TEXT,
    attachment_path TEXT,
    status TEXT NOT NULL DEFAULT 'pending_review',
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
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE(station_id, month_key, category),
    FOREIGN KEY(station_id) REFERENCES stations(id)
);

CREATE TABLE IF NOT EXISTS month_closings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    month_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    notes TEXT,
    closed_by INTEGER,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(station_id, month_key),
    FOREIGN KEY(closed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS petty_cash_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL,
    month_key TEXT NOT NULL,
    amount REAL NOT NULL CHECK(amount > 0),
    note TEXT NOT NULL,
    attachment_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review',
    created_by INTEGER NOT NULL,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    manager_note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(station_id) REFERENCES stations(id),
    FOREIGN KEY(created_by) REFERENCES users(id),
    FOREIGN KEY(reviewed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS due_settlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    note TEXT NOT NULL,
    attachment_path TEXT,
    settled_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES operations(id),
    FOREIGN KEY(settled_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS document_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    file_path TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    uploaded_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(uploaded_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_by INTEGER,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY CHECK(id=1),
    enabled INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT 'النظام تحت الصيانة',
    message TEXT NOT NULL DEFAULT 'يجري تنفيذ أعمال صيانة وتشغيل. يرجى العودة لاحقاً.',
    expected_minutes INTEGER NOT NULL DEFAULT 30,
    started_at TEXT,
    expected_end_at TEXT,
    updated_by INTEGER,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    requested_ip TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    handled_by INTEGER,
    handler_note TEXT,
    created_at TEXT NOT NULL,
    handled_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(handled_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS system_themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    css_text TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    role_target TEXT,
    station_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    link TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(station_id) REFERENCES stations(id)
);

CREATE TABLE IF NOT EXISTS help_topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    station_id INTEGER,
    user_id INTEGER,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(station_id) REFERENCES stations(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TRIGGER IF NOT EXISTS operation_actions_no_update BEFORE UPDATE ON operation_actions
BEGIN SELECT RAISE(ABORT, 'operation_actions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS operation_actions_no_delete BEFORE DELETE ON operation_actions
BEGIN SELECT RAISE(ABORT, 'operation_actions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS corrections_no_update BEFORE UPDATE ON corrections
BEGIN SELECT RAISE(ABORT, 'corrections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS corrections_no_delete BEFORE DELETE ON corrections
BEGIN SELECT RAISE(ABORT, 'corrections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events are immutable'); END;
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def get_setting(key, default=''):
    row = get_db().execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key, value, user_id=None):
    db = get_db()
    db.execute("INSERT INTO system_settings(key,value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=excluded.updated_at", (key, str(value), user_id, now()))

def get_settings():
    return {r["key"]: r["value"] for r in get_db().execute("SELECT key,value FROM system_settings").fetchall()}

def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    # Safe migration for databases created by the earlier build.
    columns = {r[1] for r in db.execute("PRAGMA table_info(stations)").fetchall()}
    if "company_name" not in columns:
        db.execute("ALTER TABLE stations ADD COLUMN company_name TEXT NOT NULL DEFAULT ''")
    columns = {r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if "must_change_password" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    seed_defaults(db)
    db.commit()


def seed_defaults(db):
    # Keep existing installations intact. Defaults are only created when absent.
    # No demo manager/collector accounts are created automatically.
    if not db.execute("SELECT 1 FROM users WHERE role='super_admin' LIMIT 1").fetchone():
        db.execute(
            """INSERT INTO users(username,password_hash,full_name,role,station_id,allowed_ip,active,must_change_password,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("admin", generate_password_hash("admin123"), "مدير النظام", "super_admin", None, "", 1, 0, now()),
        )

    # لا تُنشأ محطة أو بنود نثرية تلقائياً. السوبر أدمن هو المسؤول عن إنشاء المحطات وتهيئة بنود النثرية وسقوفها لكل شهر.
    db.execute("INSERT OR IGNORE INTO maintenance_windows(id, enabled, updated_at) VALUES(1,0,?)", (now(),))
    defaults = {
        'system_name':'نظام العمليات المالية',
        'system_tagline':'Financial Operations System',
        'login_title':'تسجيل الدخول',
        'login_subtitle':'الوصول الآمن إلى نظام العمليات المالية',
        'login_welcome':'مرحباً بك',
        'login_icon':'shield',
        'institution_logo':'',
        'footer_text':'رقابة مالية داخلية • v1.0',
        'theme':'رسمي أنيق',
        'maintenance_bypass_super_admin':'1',
        'login_description':'منصة موحدة لإدارة النثرية والاعتمادات والمستحقات والرقابة المالية.',
        'login_security_text':'واجهة وصول موحدة للمستخدمين المصرح لهم.',
        'label_approvals':'طلبات التصديق',
        'label_due':'المستحقات والسلف',
        'label_maintenance':'مركز الصيانة والتشغيل',
        'label_templates':'الاستمارات الرسمية',
        'label_station_settings':'إعدادات المحطة',
        'label_home_section':'الرئيسية',
        'label_petty_section':'النثرية',
        'label_control_section':'الرقابة والإدارة',
        'label_security_section':'الأمان',
        'label_change_password':'تغيير كلمة المرور',
        'label_internal_footer':'نظام رقابي داخلي',
    }
    for key,value in defaults.items():
        db.execute("INSERT OR IGNORE INTO system_settings(key,value,updated_at) VALUES(?,?,?)", (key,value,now()))
    help_defaults = [
        ('approval','طلبات التصديق','أدخل البيانات والمرفق ثم أرسل العملية للمراجعة. بعد الاعتماد لا يمكن تعديلها إلا بإجراء تصحيحي مسجل.'),
        ('petty_cash','النثرية','سقف البند هو تخصيص شهري وليس رصيدًا فعليًا. التمويل الفعلي لا يزيد إلا بعد اعتماد استلام النثرية.'),
        ('due','المستحقات والسلف','المستحق أو السلفة المعتمدة تمثل تمويلًا للنثرية، وتبقى التسوية والمبلغ المتبقي ظاهرين حتى الإغلاق.'),
        ('documents','المستندات','استخدم النموذج الرسمي، اطبعه ووقعه ثم صوره وارفعه لربطه بالعملية.'),
        ('maintenance','مركز الصيانة والتشغيل','هذا المركز لإدارة النظام تقنيًا. كل إجراء حساس يسجل في سجل التدقيق ولا يمكن حذف السجل من داخل النظام.'),
    ]
    for key,title,body in help_defaults:
        db.execute("INSERT OR IGNORE INTO help_topics(topic_key,title,body,created_at) VALUES(?,?,?,?)", (key,title,body,now()))
    theme_defaults = [
        ('رسمي أنيق','الهوية الافتراضية الهادئة للنظام',''),
        ('رسمي فاخر','واجهة مؤسسية فاخرة وعالية التباين',''),
        ('عصري','واجهة حديثة نظيفة ومضيئة',''),
        ('Dark Professional','واجهة داكنة احترافية',''),
        ('شبابي فاخر','واجهة حيوية راقية',''),
        ('Minimal','واجهة بسيطة شديدة الوضوح',''),
        ('Executive','واجهة تنفيذية مؤسسية',''),
        ('طبقات عائمة','واجهة غامرة بطاقات عائمة وعمق بصري مستوحى من التصميمات التفاعلية الحديثة',''),
    ]
    for name,desc,css in theme_defaults:
        db.execute("INSERT OR IGNORE INTO system_themes(name,description,css_text,created_at) VALUES(?,?,?,?)", (name,desc,css,now()))
