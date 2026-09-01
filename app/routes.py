from pathlib import Path
from datetime import datetime, timedelta
import secrets
import io
import zipfile
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory, abort, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db, now, get_setting, set_setting, get_settings
from .security import get_current_user, verify_login, login_user, logout_user, require_login, require_role, csrf_token, validate_csrf
from .services import TYPE_LABELS, STATUS_LABELS, STATUS_CLASSES, ROLE_LABELS, next_operation_number, log_action, log_event, operation_query_scope, current_month, petty_totals

bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject_globals():
    settings = get_settings()
    u = get_current_user()
    ncount = len(unread_notifications(u)) if u else 0
    return {"current_user": u, "notifications_count": ncount, "csrf_token": csrf_token, "TYPE_LABELS": TYPE_LABELS,
            "STATUS_LABELS": STATUS_LABELS, "STATUS_CLASSES": STATUS_CLASSES, "ROLE_LABELS": ROLE_LABELS,
            "SYSTEM_SETTINGS": settings, "system_name": settings.get("system_name", "نظام العمليات المالية"),
            "ui_label": lambda key, default="": settings.get("label_" + key, default)}


def push_notification(title, message, level='info', link=None, user_id=None, role_target=None, station_id=None):
    db=get_db()
    db.execute("INSERT INTO notifications(user_id,role_target,station_id,title,message,level,link,created_at) VALUES(?,?,?,?,?,?,?,?)",
               (user_id,role_target,station_id,title,message,level,link,now()))

def unread_notifications(user):
    if not user: return []
    db=get_db()
    return db.execute("SELECT * FROM notifications WHERE is_read=0 AND (user_id=? OR (user_id IS NULL AND (role_target IS NULL OR role_target=?) AND (station_id IS NULL OR station_id=?))) ORDER BY id DESC LIMIT 12", (user['id'],user['role'],user['station_id'])).fetchall()

@bp.before_app_request
def maintenance_guard():
    if request.endpoint in ("main.login", "main.logout", "main.maintenance_page", "main.forgot_password", "static"):
        return
    user = get_current_user()
    if not user:
        return
    if user["role"] == "super_admin":
        return
    row = get_db().execute("SELECT * FROM maintenance_windows WHERE id=1").fetchone()
    if row and row["enabled"]:
        return render_template("maintenance.html", maintenance=row)


@bp.before_app_request
def protect_post_requests():
    if request.endpoint in ("main.login", "main.forgot_password"):
        return
    validate_csrf()


def allowed_file(filename, extensions=None):
    extensions = extensions or current_app.config["ALLOWED_EXTENSIONS"]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in extensions


def save_attachment(file_storage, extensions=None):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename, extensions):
        flash("نوع المرفق غير مسموح.", "danger")
        return None
    filename = secure_filename(file_storage.filename) or "attachment"
    final_name = f"{now().replace(':','').replace(' ','_')}_{filename}"
    path = Path(current_app.config["UPLOAD_DIR"]) / final_name
    file_storage.save(path)
    return final_name


def require_operation_access(op, user):
    if user["role"] == "super_admin":
        return
    if op["station_id"] != user["station_id"]:
        abort(403)


def station_for_request(user):
    if user["role"] == "super_admin":
        sid = request.args.get("station_id", type=int) or request.form.get("station_id", type=int)
        if sid:
            return get_db().execute("SELECT * FROM stations WHERE id=? AND active=1", (sid,)).fetchone()
        return None
    return get_db().execute("SELECT * FROM stations WHERE id=?", (user["station_id"],)).fetchone()


def ensure_month(station_id, month_key=None):
    month_key = month_key or current_month()
    db = get_db()
    # فتح سجل الشهر الإداري فقط؛ لا يتم إنشاء أي بند أو سقف تلقائياً.
    db.execute("""INSERT OR IGNORE INTO month_closings(station_id,month_key,status,notes,created_at)
        VALUES(?,?, 'open','',?)""", (station_id,month_key,now()))


def month_open(station_id, month_key):
    row = get_db().execute("SELECT status FROM month_closings WHERE station_id=? AND month_key=?", (station_id, month_key)).fetchone()
    return not row or row["status"] != "closed"


def category_remaining(station_id, month_key, category, exclude_operation_id=None):
    db = get_db()
    item = db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? AND category=?", (station_id, month_key, category)).fetchone()
    if not item:
        return None
    sql = """SELECT COALESCE(SUM(amount),0) total FROM operations
             WHERE station_id=? AND op_type='approval' AND status='approved' AND category=?
               AND strftime('%Y-%m', created_at)=?"""
    params = [station_id, category, month_key]
    if exclude_operation_id:
        sql += " AND id<>?"
        params.append(exclude_operation_id)
    spent = db.execute(sql, params).fetchone()["total"]
    return item["allocated_amount"] - spent


def actual_balance(station_id, month_key=None, exclude_operation_id=None):
    month_key = month_key or current_month()
    t = petty_totals(station_id, month_key)
    if not exclude_operation_id:
        return t["actual"]
    db = get_db()
    op = db.execute("SELECT op_type,status,amount FROM operations WHERE id=?", (exclude_operation_id,)).fetchone()
    if not op or op["status"] != "approved":
        return t["actual"]
    if op["op_type"] == "approval":
        return t["actual"] + op["amount"]
    if op["op_type"] == "due":
        return t["actual"] - op["amount"]
    return t["actual"]


@bp.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        user = verify_login(request.form.get("username", ""), request.form.get("password", ""))
        if user:
            login_user(user)
            flash("تم تسجيل الدخول بنجاح.", "success")
            return redirect(url_for("main.dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "danger")
    return render_template("login.html")


@bp.get("/maintenance-status")
def maintenance_page():
    row = get_db().execute("SELECT * FROM maintenance_windows WHERE id=1").fetchone()
    if not row or not row["enabled"]:
        return redirect(url_for("main.login"))
    return render_template("maintenance.html", maintenance=row)

@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if get_current_user():
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        db = get_db()
        user = db.execute("SELECT id,username FROM users WHERE username=? AND active=1", (username,)).fetchone()
        # Do not disclose whether the account exists.
        if user:
            pending = db.execute("SELECT id FROM password_reset_requests WHERE user_id=? AND status='pending'", (user["id"],)).fetchone()
            if not pending:
                db.execute("INSERT INTO password_reset_requests(user_id,username,requested_ip,status,created_at) VALUES(?,?,?,'pending',?)", (user["id"], user["username"], request.remote_addr or "", now()))
                log_event("password_reset_requested", f"طلب استعادة كلمة مرور للمستخدم {user['username']}", user["id"], None)
                push_notification("طلب استعادة كلمة مرور", f"المستخدم {user['username']} طلب استعادة كلمة المرور.", "warning", url_for("main.maintenance_center", section="passwords"), role_target="super_admin")
                db.commit()
        flash("تم تسجيل الطلب. إذا كان الحساب موجودًا فسيظهر طلبه لدى مدير النظام.", "info")
        return redirect(url_for("main.login"))
    return render_template("forgot_password.html")


@bp.route("/logout")
def logout():
    logout_user()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("main.login"))


def attention_items(user):
    db=get_db(); items=[]
    if not user: return items
    if user["role"] in ("manager","super_admin"):
        q="SELECT COUNT(*) c FROM operations WHERE status='pending_review'"
        params=[]
        if user["role"]!="super_admin": q += " AND station_id=?"; params.append(user["station_id"])
        n=db.execute(q,params).fetchone()["c"]
        if n: items.append({"level":"warning","text":f"{n} عملية تنتظر المراجعة.","link":url_for("main.operations_list",op_type="approval")})
    q="SELECT COUNT(*) c FROM operations WHERE status='returned' AND created_by=?"
    n=db.execute(q,(user["id"],)).fetchone()["c"]
    if n: items.append({"level":"warning","text":f"لديك {n} عملية أعيدت للتصحيح.","link":url_for("main.operations_list",op_type="approval")})
    n=db.execute("SELECT COUNT(*) c FROM notifications WHERE is_read=0 AND (user_id=? OR (user_id IS NULL AND (role_target IS NULL OR role_target=?) AND (station_id IS NULL OR station_id=?)))",(user["id"],user["role"],user["station_id"])).fetchone()["c"]
    if n: items.append({"level":"info","text":f"لديك {n} تنبيه غير مقروء.","link":url_for("main.notifications")})
    if user["role"]=="super_admin":
        n=db.execute("SELECT COUNT(*) c FROM password_reset_requests WHERE status='pending'").fetchone()["c"]
        if n: items.append({"level":"danger","text":f"{n} طلب استعادة كلمة مرور يحتاج معالجة.","link":url_for("main.maintenance_center",section="passwords")})
    return items[:8]

def operation_step(op):
    if op["status"] in ("closed",): return (7,"الإغلاق")
    if op["status"] == "approved": return (5,"التنفيذ")
    if op["status"] == "returned": return (3,"التصحيح")
    if op["status"] == "rejected": return (3,"المراجعة")
    return (2,"المراجعة")

@bp.route("/")
@require_login
def dashboard():
    user = get_current_user()
    db = get_db()
    if user["role"] == "super_admin":
        stations = db.execute("SELECT * FROM stations ORDER BY active DESC, name").fetchall()
        station_stats = []
        for s in stations:
            ensure_month(s["id"])
            totals = petty_totals(s["id"])
            pending = db.execute("SELECT COUNT(*) c FROM operations WHERE station_id=? AND op_type IN ('approval','due') AND status='pending_review'", (s["id"],)).fetchone()["c"]
            station_stats.append({"station": s, "totals": totals, "pending": pending})
        db.commit()
        users_count = db.execute("SELECT COUNT(*) c FROM users WHERE active=1").fetchone()["c"]
        managers = db.execute("SELECT COUNT(*) c FROM users WHERE active=1 AND role='manager'").fetchone()["c"]
        collectors = db.execute("SELECT COUNT(*) c FROM users WHERE active=1 AND role='collector'").fetchone()["c"]
        recent = db.execute("""SELECT a.*,u.full_name AS user_name,s.name AS station_name
            FROM audit_events a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN stations s ON s.id=a.station_id
            ORDER BY a.created_at DESC LIMIT 10""").fetchall()
        return render_template("super_dashboard.html", stations=station_stats, users_count=users_count, managers=managers,
                               collectors=collectors, recent=recent, month_key=current_month(), notifications=unread_notifications(user), attention=attention_items(user))

    station = station_for_request(user)
    ensure_month(station["id"])
    totals = petty_totals(station["id"])
    pending = db.execute("SELECT COUNT(*) c FROM operations WHERE station_id=? AND op_type IN ('approval','due') AND status='pending_review'", (station["id"],)).fetchone()["c"]
    returned = db.execute("SELECT COUNT(*) c FROM operations WHERE station_id=? AND op_type IN ('approval','due') AND status='returned'", (station["id"],)).fetchone()["c"]
    recent = db.execute("""SELECT o.*,u.full_name AS creator_name FROM operations o
        LEFT JOIN users u ON u.id=o.created_by WHERE o.station_id=? AND o.op_type IN ('approval','due') ORDER BY o.created_at DESC LIMIT 8""", (station["id"],)).fetchall()
    alerts = []
    if pending:
        alerts.append(("warning", f"توجد {pending} عملية بانتظار اعتماد المدير."))
    if returned:
        alerts.append(("info", f"توجد {returned} عملية مرتجعة للتصحيح."))
    if totals["actual"] < 0:
        alerts.append(("danger", "رصيد النثرية الفعلي سالب ويحتاج معالجة رقابية."))
    closing = db.execute("SELECT status FROM month_closings WHERE station_id=? AND month_key=?", (station["id"], current_month())).fetchone()
    if not closing or closing["status"] != "closed":
        alerts.append(("warning", "الشهر الحالي لم يتم قفله بعد."))
    return render_template("dashboard.html", station=station, totals=totals, pending=pending, returned=returned,
                           recent=recent, alerts=alerts, month_key=current_month(), notifications=unread_notifications(user), attention=attention_items(user))


@bp.route("/operations/<op_type>")
@require_login
def operations_list(op_type):
    if op_type not in TYPE_LABELS:
        abort(404)
    user = get_current_user()
    db = get_db()
    where, params = operation_query_scope(user)
    status = request.args.get("status", "")
    q = request.args.get("q", "").strip()
    sql = f"""SELECT o.*,u.full_name AS creator_name,r.full_name AS reviewer_name,s.name AS station_name
              FROM operations o LEFT JOIN users u ON u.id=o.created_by
              LEFT JOIN users r ON r.id=o.reviewed_by LEFT JOIN stations s ON s.id=o.station_id
              WHERE {where} AND o.op_type=?"""
    values = [*params, op_type]
    if status:
        sql += " AND o.status=?"; values.append(status)
    if q:
        sql += " AND (o.op_no LIKE ? OR o.title LIKE ? OR o.category LIKE ? OR s.name LIKE ?)"
        values.extend([f"%{q}%"] * 4)
    sql += " ORDER BY o.created_at DESC"
    rows = db.execute(sql, values).fetchall()
    return render_template("operations_list.html", rows=rows, op_type=op_type, status=status, q=q)


@bp.route("/operations/<op_type>/new", methods=["GET", "POST"])
@require_login
def operation_new(op_type):
    if op_type not in TYPE_LABELS:
        abort(404)
    user = get_current_user()
    if user["role"] not in ("collector", "manager"):
        abort(403)
    station = station_for_request(user)
    month_key = current_month()
    ensure_month(station["id"], month_key)
    db = get_db()
    categories = db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id", (station["id"], month_key)).fetchall()
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount") or 0)
        except ValueError:
            amount = 0
        if amount <= 0:
            flash("المبلغ يجب أن يكون أكبر من صفر.", "danger")
            return render_template("operation_form.html", op_type=op_type, op=None, categories=categories, actual=petty_totals(station["id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())
        if not month_open(station["id"], month_key):
            flash("الشهر مقفل ولا يمكن إضافة عملية جديدة.", "danger")
            return redirect(url_for("main.operations_list", op_type=op_type))
        category = request.form.get("category", "").strip()
        if op_type == "approval":
            remaining = category_remaining(station["id"], month_key, category)
            if remaining is None:
                flash("يجب اختيار بند نثرية معتمد.", "danger")
                return render_template("operation_form.html", op_type=op_type, op=None, categories=categories, actual=petty_totals(station["id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())
            if amount > remaining:
                flash(f"المبلغ يتجاوز المتبقي في بند {category}: {remaining:,.0f}.", "danger")
                return render_template("operation_form.html", op_type=op_type, op=None, categories=categories, actual=petty_totals(station["id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())
        attachment = save_attachment(request.files.get("attachment"))
        if not attachment:
            flash("المرفق إلزامي لإكمال الدورة المالية.", "danger")
            return render_template("operation_form.html", op_type=op_type, op=None, categories=categories, actual=petty_totals(station["id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())
        op_no = next_operation_number(station["id"], op_type)
        title = request.form.get("title") or ("طلب تصديق من النثرية" if op_type == "approval" else "إضافة مستحق / سلفة للنثرية")
        description = request.form.get("description", "").strip()
        cur = db.execute("""INSERT INTO operations(station_id,op_no,op_type,title,category,amount,allocated_amount,
            description,attachment_path,status,locked,created_by,created_at,updated_at)
            VALUES(?,?,?,?,?,?,NULL,?,?,'pending_review',0,?,?,?)""",
            (station["id"], op_no, op_type, title, category, amount, description, attachment, user["id"], now(), now()))
        operation_id = cur.lastrowid
        log_action(operation_id, "إنشاء عملية", None, "pending_review", "تم إنشاء العملية وإرسالها للمراجعة.", user["id"])
        log_event("operation_created", f"إنشاء {TYPE_LABELS[op_type]} {op_no}", user["id"], station["id"])
        push_notification("عملية جديدة", f"العملية {op_no} تنتظر المراجعة.", "warning", url_for("main.operation_detail",operation_id=operation_id), role_target="manager", station_id=station["id"])
        db.commit()
        flash(f"تم إنشاء العملية بالرقم {op_no} وهي الآن قيد مراجعة المدير.", "success")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    return render_template("operation_form.html", op_type=op_type, op=None, categories=categories, actual=petty_totals(station["id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())


@bp.route("/operation/<int:operation_id>")
@require_login
def operation_detail(operation_id):
    user = get_current_user(); db = get_db()
    op = db.execute("""SELECT o.*,s.name AS station_name,s.company_name,s.manager_name,
        u.full_name AS creator_name,r.full_name AS reviewer_name FROM operations o JOIN stations s ON s.id=o.station_id
        LEFT JOIN users u ON u.id=o.created_by LEFT JOIN users r ON r.id=o.reviewed_by WHERE o.id=?""", (operation_id,)).fetchone()
    if not op or op["op_type"] not in TYPE_LABELS: abort(404)
    require_operation_access(op, user)
    actions = db.execute("SELECT a.*,u.full_name AS user_name FROM operation_actions a LEFT JOIN users u ON u.id=a.user_id WHERE a.operation_id=? ORDER BY a.created_at DESC", (operation_id,)).fetchall()
    corrections = db.execute("SELECT c.*,u.full_name AS user_name FROM corrections c LEFT JOIN users u ON u.id=c.created_by WHERE c.operation_id=? ORDER BY c.created_at DESC", (operation_id,)).fetchall()
    settled = db.execute("SELECT COALESCE(SUM(amount),0) total FROM due_settlements WHERE operation_id=?", (operation_id,)).fetchone()["total"]
    templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall()
    step_no,step_label=operation_step(op)
    return render_template("operation_detail.html", op=op, actions=actions, corrections=corrections, settled=settled,
                           unsettled=max(0, op["amount"] - settled), balance=petty_totals(op["station_id"])["actual"],
                           current_step=step_no, current_step_label=step_label, templates=templates)


@bp.get("/operation/<int:operation_id>/resume")
@require_login
def operation_resume(operation_id):
    user=get_current_user(); db=get_db(); op=db.execute("SELECT * FROM operations WHERE id=?",(operation_id,)).fetchone()
    if not op: abort(404)
    require_operation_access(op,user)
    if op["locked"] or op["status"] in ("approved","closed"):
        return redirect(url_for("main.operation_detail",operation_id=operation_id))
    return redirect(url_for("main.operation_edit",operation_id=operation_id))

@bp.route("/operation/<int:operation_id>/edit", methods=["GET", "POST"])
@require_login
def operation_edit(operation_id):
    user = get_current_user(); db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op or op["op_type"] not in TYPE_LABELS: abort(404)
    require_operation_access(op, user)
    if op["locked"] or op["status"] == "approved":
        flash("لا يمكن تعديل عملية معتمدة. استخدم إجراءً تصحيحياً مسجلاً.", "danger")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    if user["role"] == "collector" and op["created_by"] != user["id"]: abort(403)
    station = db.execute("SELECT * FROM stations WHERE id=?", (op["station_id"],)).fetchone()
    categories = db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id", (op["station_id"], current_month())).fetchall()
    if request.method == "POST":
        try: amount = float(request.form.get("amount") or 0)
        except ValueError: amount = 0
        category = request.form.get("category", "").strip()
        if amount <= 0: flash("المبلغ يجب أن يكون أكبر من صفر.", "danger"); return redirect(url_for("main.operation_edit", operation_id=operation_id))
        if op["op_type"] == "approval":
            rem = category_remaining(op["station_id"], current_month(), category, operation_id)
            if rem is None or amount > rem:
                flash("المبلغ يتجاوز المتاح في البند المحدد.", "danger"); return redirect(url_for("main.operation_edit", operation_id=operation_id))
        attachment = op["attachment_path"]
        new_file = request.files.get("attachment")
        if new_file and new_file.filename: attachment = save_attachment(new_file) or attachment
        db.execute("""UPDATE operations SET title=?,category=?,amount=?,description=?,attachment_path=?,status='pending_review',updated_at=? WHERE id=?""",
                   (request.form.get("title") or TYPE_LABELS[op["op_type"]], category, amount, request.form.get("description", ""), attachment, now(), operation_id))
        log_action(operation_id, "تعديل وإعادة إرسال", op["status"], "pending_review", "تم تعديل العملية وإعادتها للمراجعة.", user["id"])
        db.commit(); flash("تم تعديل العملية وإعادتها لقائمة المراجعة.", "success")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    return render_template("operation_form.html", op_type=op["op_type"], op=op, categories=categories, actual=petty_totals(op["station_id"])["actual"], templates=db.execute("SELECT * FROM document_templates WHERE active=1 ORDER BY created_at DESC").fetchall())


@bp.post("/operation/<int:operation_id>/review/<action>")
@require_role("manager", "super_admin")
def operation_review(operation_id, action):
    if action not in ("approve", "return", "reject"): abort(404)
    user = get_current_user(); db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op or op["op_type"] not in TYPE_LABELS: abort(404)
    require_operation_access(op, user)
    if op["locked"] or op["status"] == "approved":
        flash("هذه العملية معتمدة ومقفلة بالفعل.", "warning"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    note = request.form.get("manager_note", "").strip()
    if action == "approve":
        op_month = (op["created_at"] or current_month())[:7]
        if not month_open(op["station_id"], op_month):
            flash("الشهر مقفل.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
        if op["op_type"] == "approval":
            rem = category_remaining(op["station_id"], op_month, op["category"], operation_id)
            bal = actual_balance(op["station_id"], op_month, operation_id)
            if rem is None or op["amount"] > rem:
                flash("لا يمكن اعتماد الطلب: المبلغ يتجاوز المتبقي في البند.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
            if op["amount"] > bal:
                flash(f"لا يمكن اعتماد الطلب: رصيد النثرية الفعلي المتاح {bal:,.0f}.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    mapping = {"approve": ("approved", "اعتماد"), "return": ("returned", "إرجاع للتصحيح"), "reject": ("rejected", "رفض")}
    new_status, label = mapping[action]
    db.execute("UPDATE operations SET status=?,locked=?,reviewed_by=?,reviewed_at=?,manager_note=?,updated_at=? WHERE id=?",
               (new_status, 1 if new_status == "approved" else 0, user["id"], now(), note, now(), operation_id))
    log_action(operation_id, label, op["status"], new_status, note, user["id"])
    log_event("operation_review", f"{label} العملية {op['op_no']}", user["id"], op["station_id"])
    level = "success" if action == "approve" else ("warning" if action == "return" else "danger")
    push_notification(f"{label} العملية", f"العملية {op['op_no']} — {label}.", level, url_for("main.operation_detail", operation_id=operation_id), user_id=op["created_by"])
    db.commit(); flash(f"تم تنفيذ إجراء: {label}.", "success")
    return redirect(url_for("main.operation_detail", operation_id=operation_id))


@bp.post("/operation/<int:operation_id>/correct")
@require_role("manager", "super_admin")
def operation_correct(operation_id):
    user = get_current_user(); db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op or op["op_type"] not in TYPE_LABELS: abort(404)
    require_operation_access(op, user)
    if op["status"] != "approved":
        flash("الإجراء التصحيحي مخصص للعمليات المعتمدة فقط.", "warning"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    reason = request.form.get("reason", "").strip()
    if not reason: flash("سبب التصحيح إلزامي.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    fields = {"amount": request.form.get("amount"), "category": request.form.get("category"), "description": request.form.get("description")}
    updates = []
    for field, new_value in fields.items():
        if new_value is None or str(new_value).strip() == "": continue
        old_value = str(op[field] or "")
        value = float(new_value) if field == "amount" else new_value
        if str(value) != old_value: updates.append((field, old_value, str(value), value))
    if not updates: flash("لا توجد قيمة جديدة للتصحيح.", "info"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    new_amount = next((v for f,_,_,v in updates if f == "amount"), op["amount"])
    new_category = next((v for f,_,_,v in updates if f == "category"), op["category"])
    if new_amount <= 0: flash("المبلغ يجب أن يكون أكبر من صفر.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    if op["op_type"] == "approval":
        op_month = (op["created_at"] or current_month())[:7]
        rem = category_remaining(op["station_id"], op_month, new_category, operation_id)
        bal = actual_balance(op["station_id"], op_month, operation_id)
        if rem is None or new_amount > rem or new_amount > bal:
            flash("القيمة الجديدة تتجاوز الرصيد أو المتبقي في البند.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    if op["op_type"] == "due":
        settled = db.execute("SELECT COALESCE(SUM(amount),0) total FROM due_settlements WHERE operation_id=?", (operation_id,)).fetchone()["total"]
        if new_amount < settled:
            flash("لا يمكن خفض المستحق إلى أقل من المبلغ الذي تمت تسويته.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    for field, old_value, new_value, value in updates:
        db.execute("INSERT INTO corrections(operation_id,field_name,old_value,new_value,reason,created_by,ip_address,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (operation_id, field, old_value, new_value, reason, user["id"], request.remote_addr or "", now()))
        db.execute(f"UPDATE operations SET {field}=?,updated_at=? WHERE id=?", (value, now(), operation_id))
    log_action(operation_id, "إجراء تصحيحي", "approved", "approved", reason, user["id"])
    db.commit(); flash("تم تنفيذ الإجراء التصحيحي وتسجيله في سجل التدقيق.", "success")
    return redirect(url_for("main.operation_detail", operation_id=operation_id))


@bp.post("/operation/<int:operation_id>/settle")
@require_role("manager", "super_admin")
def settle_due(operation_id):
    user = get_current_user(); db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=? AND op_type='due'", (operation_id,)).fetchone()
    if not op: abort(404)
    require_operation_access(op, user)
    if op["status"] != "approved":
        flash("لا يمكن تسوية مستحق غير معتمد.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    try: amount = float(request.form.get("amount") or 0)
    except ValueError: amount = 0
    settled = db.execute("SELECT COALESCE(SUM(amount),0) total FROM due_settlements WHERE operation_id=?", (operation_id,)).fetchone()["total"]
    remaining = op["amount"] - settled
    if amount <= 0 or amount > remaining:
        flash(f"مبلغ التسوية يجب ألا يتجاوز المتبقي {remaining:,.0f}.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    attachment = save_attachment(request.files.get("attachment"))
    if not attachment:
        flash("مرفق إثبات التسوية إلزامي.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    note = request.form.get("note", "").strip()
    if not note: flash("ملاحظة التسوية إلزامية.", "danger"); return redirect(url_for("main.operation_detail", operation_id=operation_id))
    db.execute("INSERT INTO due_settlements(operation_id,amount,note,attachment_path,settled_by,created_at) VALUES(?,?,?,?,?,?)",
               (operation_id, amount, note, attachment, user["id"], now()))
    new_total = settled + amount
    if new_total >= op["amount"]:
        db.execute("UPDATE operations SET status='closed',locked=1,updated_at=? WHERE id=?", (now(), operation_id))
        log_action(operation_id, "تسوية المستحق بالكامل", "approved", "closed", note, user["id"])
    else:
        log_action(operation_id, "تسوية جزئية للمستحق", "approved", "approved", note, user["id"])
    log_event("due_settlement", f"تسوية مستحق {op['op_no']} بمبلغ {amount:,.0f}", user["id"], op["station_id"])
    db.commit(); flash("تم تسجيل إعادة المبلغ للنثرية وتحديث رصيدها الفعلي.", "success")
    return redirect(url_for("main.operation_detail", operation_id=operation_id))


@bp.route("/operation/<int:operation_id>/print")
@require_login
def operation_print(operation_id):
    user = get_current_user(); db = get_db()
    op = db.execute("""SELECT o.*,s.name AS station_name,s.company_name,s.manager_name,s.address,s.phone,
        u.full_name AS creator_name,r.full_name AS reviewer_name FROM operations o JOIN stations s ON s.id=o.station_id
        LEFT JOIN users u ON u.id=o.created_by LEFT JOIN users r ON r.id=o.reviewed_by WHERE o.id=?""", (operation_id,)).fetchone()
    if not op or op["op_type"] not in TYPE_LABELS: abort(404)
    require_operation_access(op, user)
    return render_template("print_operation.html", op=op)


@bp.route("/uploads/<path:filename>")
@require_login
def uploads(filename):
    return send_from_directory(current_app.config["UPLOAD_DIR"], filename)


@bp.route("/petty-cash")
@require_login
def petty_cash():
    user = get_current_user(); db = get_db()
    if user["role"] == "super_admin":
        abort(403)
    month_key = request.args.get("month") or current_month()
    station = station_for_request(user); ensure_month(station["id"], month_key)
    rows = db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id", (station["id"], month_key)).fetchall()
    enriched=[]
    for row in rows:
        spent = db.execute("""SELECT COALESCE(SUM(amount),0) total FROM operations WHERE station_id=? AND op_type='approval'
            AND status IN ('approved','closed') AND category=? AND strftime('%Y-%m',created_at)=?""", (station["id"],row["category"],month_key)).fetchone()["total"]
        enriched.append({"row":row,"spent":spent,"remaining":row["allocated_amount"]-spent})
    totals=petty_totals(station["id"],month_key)
    receipts=db.execute("SELECT r.*,u.full_name AS creator_name,v.full_name AS reviewer_name FROM petty_cash_receipts r LEFT JOIN users u ON u.id=r.created_by LEFT JOIN users v ON v.id=r.reviewed_by WHERE r.station_id=? AND r.month_key=? ORDER BY r.created_at DESC",(station["id"],month_key)).fetchall()
    return render_template("petty_cash.html", rows=enriched, month_key=month_key, totals=totals, station=station, receipts=receipts)


@bp.route("/petty-cash/receipt/new", methods=["GET", "POST"])
@require_role("collector", "manager", "super_admin")
def petty_cash_receipt_new():
    user=get_current_user(); db=get_db()
    if user["role"] == "super_admin":
        station_id=request.form.get("station_id",type=int) or request.args.get("station_id",type=int)
        station=db.execute("SELECT * FROM stations WHERE id=? AND active=1",(station_id,)).fetchone() if station_id else None
    else:
        station=station_for_request(user)
    month_key=(request.form.get("month_key") or request.args.get("month") or current_month()).strip()
    if not station:
        flash("يجب اختيار محطة نشطة لتسجيل استلام النثرية.","danger"); return redirect(url_for("main.petty_cash"))
    ensure_month(station["id"],month_key)
    if not month_open(station["id"],month_key):
        flash("الشهر مقفل ولا يمكن تسجيل استلام نثرية جديد.","danger"); return redirect(url_for("main.petty_cash",month=month_key))
    if request.method == "POST":
        try: amount=float(request.form.get("amount") or 0)
        except ValueError: amount=0
        note=request.form.get("note","").strip()
        attachment=save_attachment(request.files.get("attachment"))
        if amount<=0: flash("مبلغ استلام النثرية يجب أن يكون أكبر من صفر.","danger")
        elif not note: flash("بيان استلام النثرية إلزامي.","danger")
        elif not attachment: flash("مرفق إثبات استلام النثرية إلزامي.","danger")
        else:
            db.execute("INSERT INTO petty_cash_receipts(station_id,month_key,amount,note,attachment_path,status,created_by,created_at) VALUES(?,?,?,?,?,'pending_review',?,?)",(station["id"],month_key,amount,note,attachment,user["id"],now()))
            log_event("petty_cash_receipt_created",f"تسجيل استلام نثرية بمبلغ {amount:,.0f} لشهر {month_key}",user["id"],station["id"])
            push_notification("استلام نثرية بانتظار الاعتماد", f"طلب استلام نثرية بمبلغ {amount:,.0f} للمحطة {station['name']}.", "warning", url_for("main.petty_cash", month=month_key), role_target="manager", station_id=station["id"])
            db.commit()
            flash("تم تسجيل استلام النثرية وإرساله للمراجعة.","success")
            return redirect(url_for("main.petty_cash",month=month_key))
    return render_template("petty_cash_receipt_form.html",station=station,month_key=month_key)

@bp.post("/petty-cash/receipt/<int:receipt_id>/review/<action>")
@require_role("manager", "super_admin")
def petty_cash_receipt_review(receipt_id, action):
    if action not in ("approve","return","reject"): abort(404)
    db=get_db(); user=get_current_user()
    row=db.execute("SELECT * FROM petty_cash_receipts WHERE id=?",(receipt_id,)).fetchone()
    if not row: abort(404)
    if user["role"] != "super_admin" and row["station_id"] != user["station_id"]: abort(403)
    if row["status"] not in ("pending_review","returned"): flash("هذا الطلب تمت معالجته بالفعل.","warning"); return redirect(url_for("main.petty_cash",month=row["month_key"]))
    if not month_open(row["station_id"],row["month_key"]): flash("الشهر مقفل.","danger"); return redirect(url_for("main.petty_cash",month=row["month_key"]))
    note=request.form.get("manager_note","").strip()
    if action in ("return","reject") and not note:
        flash("سبب الإرجاع أو الرفض إلزامي.","danger"); return redirect(url_for("main.petty_cash",month=row["month_key"]))
    status={"approve":"approved","return":"returned","reject":"rejected"}[action]
    db.execute("UPDATE petty_cash_receipts SET status=?,reviewed_by=?,reviewed_at=?,manager_note=? WHERE id=?",(status,user["id"],now(),note,receipt_id))
    log_event("petty_cash_receipt_review",f"{action} استلام النثرية #{receipt_id} بمبلغ {row['amount']:,.0f}",user["id"],row["station_id"]); db.commit()
    flash({"approve":"تم اعتماد استلام النثرية وإضافته إلى الرصيد الفعلي.","return":"تم إرجاع طلب استلام النثرية للتصحيح.","reject":"تم رفض طلب استلام النثرية."}[action],"success" if action=="approve" else "info")
    return redirect(url_for("main.petty_cash",month=row["month_key"]))

@bp.route("/month/close", methods=["POST"])
@require_role("manager", "super_admin")
def close_month():
    user=get_current_user(); db=get_db(); station=station_for_request(user); month_key=request.form.get("month_key") or current_month()
    ensure_month(station["id"],month_key)
    open_due=db.execute("SELECT COUNT(*) c FROM operations WHERE station_id=? AND op_type='due' AND status='approved' AND amount>(SELECT COALESCE(SUM(amount),0) FROM due_settlements WHERE operation_id=operations.id) AND strftime('%Y-%m',created_at)=?",(station["id"],month_key)).fetchone()["c"]
    if open_due: flash("لا يمكن قفل الشهر مع وجود مستحقات غير مسوّاة.","danger"); return redirect(url_for("main.petty_cash",month=month_key))
    pending_receipts=db.execute("SELECT COUNT(*) c FROM petty_cash_receipts WHERE station_id=? AND month_key=? AND status IN ('pending_review','returned')",(station["id"],month_key)).fetchone()["c"]
    if pending_receipts: flash("لا يمكن قفل الشهر مع وجود طلبات استلام نثرية غير مكتملة.","danger"); return redirect(url_for("main.petty_cash",month=month_key))
    db.execute("UPDATE month_closings SET status='closed',closed_by=?,closed_at=?,notes=? WHERE station_id=? AND month_key=?",(user["id"],now(),request.form.get("notes",""),station["id"],month_key))
    log_event("month_closed",f"إغلاق شهر {month_key}",user["id"],station["id"]); db.commit(); flash("تم قفل الشهر بنجاح.","success")
    return redirect(url_for("main.petty_cash",month=month_key))


@bp.post("/maintenance/petty-cash/config")
@require_role("super_admin")
def maintenance_petty_config():
    db = get_db(); user = get_current_user()
    station_id = request.form.get("station_id", type=int)
    month_key = (request.form.get("month_key") or current_month()).strip()
    if not station_id or not db.execute("SELECT id FROM stations WHERE id=?", (station_id,)).fetchone():
        flash("يجب اختيار محطة.", "danger")
        return redirect(url_for("main.maintenance_center",section="petty"))
    try:
        parsed = datetime.strptime(month_key, "%Y-%m")
        month_key = parsed.strftime("%Y-%m")
    except ValueError:
        flash("صيغة الشهر غير صحيحة. استخدم YYYY-MM.", "danger")
        return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))
    if not month_open(station_id, month_key):
        flash("الشهر مقفل ولا يمكن تعديل تهيئة النثرية.", "danger")
        return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))

    submitted = []
    for key, value in request.form.items():
        if not key.startswith("petty_id_"):
            continue
        idx = key.rsplit("_", 1)[-1]
        item_id = request.form.get(key, type=int)
        category = (request.form.get("petty_category_" + idx) or "").strip()
        try:
            amount = float(request.form.get("petty_amount_" + idx) or 0)
        except ValueError:
            amount = -1
        if not item_id or not category or amount < 0:
            flash("بيانات أحد بنود النثرية غير صحيحة.", "danger")
            return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))
        submitted.append((item_id, category, amount))

    new_category = (request.form.get("new_category") or "").strip()
    new_amount_raw = request.form.get("new_amount")
    new_item = None
    if new_category or (new_amount_raw not in (None, "")):
        try:
            new_amount = float(new_amount_raw or 0)
        except ValueError:
            new_amount = -1
        if not new_category or new_amount < 0:
            flash("بيانات البند الجديد غير صحيحة.", "danger")
            return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))
        new_item = (new_category, new_amount)

    if not submitted and not new_item:
        flash("أدخل بندًا واحدًا على الأقل.", "danger")
        return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))

    try:
        existing_ids = {r["id"]: r for r in db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=?", (station_id, month_key)).fetchall()}
        seen_categories = set()
        for item_id, category, amount in submitted:
            old = existing_ids.get(item_id)
            if not old:
                raise ValueError("البند غير مرتبط بالمحطة أو الشهر المحدد.")
            if category in seen_categories:
                raise ValueError("لا يمكن تكرار اسم البند في نفس الشهر.")
            seen_categories.add(category)
            if amount < old["spent_amount"]:
                raise ValueError(f"سقف البند {old['category']} لا يمكن أن يكون أقل من المصروف الحالي ({old['spent_amount']:,.0f}).")
            if old["spent_amount"] > 0 and category != old["category"]:
                raise ValueError(f"لا يمكن تغيير اسم البند {old['category']} بعد وجود مصروفات عليه.")
            conflict = db.execute("SELECT id FROM petty_cash_items WHERE station_id=? AND month_key=? AND category=? AND id<>?", (station_id, month_key, category, item_id)).fetchone()
            if conflict:
                raise ValueError(f"اسم البند {category} مستخدم بالفعل.")
            db.execute("UPDATE petty_cash_items SET category=?,allocated_amount=? WHERE id=?", (category, amount, item_id))
        if new_item:
            category, amount = new_item
            if category in seen_categories or db.execute("SELECT id FROM petty_cash_items WHERE station_id=? AND month_key=? AND category=?", (station_id, month_key, category)).fetchone():
                raise ValueError(f"اسم البند {category} مستخدم بالفعل.")
            db.execute("INSERT INTO petty_cash_items(station_id,month_key,category,allocated_amount,spent_amount,status,created_at) VALUES(?,?,?, ?,0,'active',?)", (station_id, month_key, category, amount, now()))
        ensure_month(station_id, month_key)
        total = db.execute("SELECT COALESCE(SUM(allocated_amount),0) total FROM petty_cash_items WHERE station_id=? AND month_key=? AND status='active'", (station_id, month_key)).fetchone()["total"]
        log_event("petty_cash_configuration_changed", f"تهيئة بنود النثرية للمحطة #{station_id} لشهر {month_key} — إجمالي السقوف {total:,.0f}", user["id"], station_id)
        db.commit()
        flash("تم حفظ تهيئة بنود النثرية بنجاح. لم تتم إضافة أي مبلغ إلى الرصيد الفعلي.", "success")
    except ValueError as exc:
        db.rollback(); flash(str(exc), "danger")
    except Exception:
        db.rollback(); flash("تعذر حفظ تهيئة النثرية بسبب خطأ غير متوقع.", "danger")
    return redirect(url_for("main.maintenance_center", tab="petty", station_id=station_id, month=month_key))

@bp.route("/maintenance", methods=["GET", "POST"])
@bp.route("/maintenance/<section>", methods=["GET", "POST"], strict_slashes=False)
@require_role("super_admin")
def maintenance_center(section=None):
    db = get_db()
    section_map = {
        "overview": "maintenance_overview.html",
        "stations": "maintenance_stations.html",
        "users": "maintenance_users.html",
        "passwords": "maintenance_passwords.html",
        "sessions": "maintenance_sessions.html",
        "identity": "maintenance_identity.html",
        "themes": "maintenance_themes.html",
        "templates": "maintenance_templates.html",
        "petty": "maintenance_petty.html",
        "system": "maintenance_system.html",
        "monitor": "maintenance_monitor.html",
        "audit": "maintenance_audit.html",
    }
    if request.method == "GET" and not section:
        requested_tab = request.args.get("tab")
        if requested_tab in section_map and requested_tab != "overview":
            return redirect(url_for("main.maintenance_center", section=requested_tab, **{k:v for k,v in request.args.items() if k != "tab"}))
        section = "overview"
    if section not in section_map:
        return redirect(url_for("main.maintenance_center", section="overview"))
    if request.method == "POST":
        action = request.form.get("action")
        user = get_current_user()
        if action == "save_maintenance":
            enabled = 1 if request.form.get("enabled") == "1" else 0
            title = request.form.get("maintenance_title", "النظام تحت الصيانة").strip() or "النظام تحت الصيانة"
            message = request.form.get("maintenance_message", "").strip() or "يجري تنفيذ أعمال صيانة وتشغيل. يرجى العودة لاحقاً."
            try: minutes = max(1, min(10080, int(request.form.get("expected_minutes") or 30)))
            except ValueError: minutes = 30
            started = now() if enabled else None
            from datetime import datetime, timedelta
            expected = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S") if enabled else None
            db.execute("UPDATE maintenance_windows SET enabled=?,title=?,message=?,expected_minutes=?,started_at=?,expected_end_at=?,updated_by=?,updated_at=? WHERE id=1", (enabled,title,message,minutes,started,expected,user["id"],now()))
            log_event("maintenance_changed", "تغيير حالة وضع الصيانة" + (" إلى مفعّل" if enabled else " إلى متوقف"), user["id"], None)
            push_notification("وضع الصيانة", "تم تغيير حالة وضع الصيانة.", "warning", url_for("main.maintenance_center",section="overview"), user_id=user["id"])
            db.commit(); flash("تم حفظ إعدادات وضع الصيانة.", "success")
        elif action == "save_settings":
            keys = ["system_name","system_tagline","login_title","login_subtitle","login_welcome","login_icon","footer_text","login_description","login_security_text"]
            for key in keys:
                set_setting(key, request.form.get(key,""), user["id"])
            logo = request.files.get("institution_logo_file")
            if logo and logo.filename:
                logo_name = save_attachment(logo, {"png","jpg","jpeg"})
                if logo_name:
                    set_setting("institution_logo", logo_name, user["id"])
            elif request.form.get("institution_logo", "").strip():
                set_setting("institution_logo", request.form.get("institution_logo", "").strip(), user["id"])
            theme = request.form.get("theme", get_setting("theme", "رسمي أنيق"))
            selected_theme = db.execute("SELECT name, css_text FROM system_themes WHERE name=? AND active=1", (theme,)).fetchone()
            if not selected_theme:
                theme = "رسمي أنيق"
                selected_theme = db.execute("SELECT name, css_text FROM system_themes WHERE name=? AND active=1", (theme,)).fetchone()
            set_setting("theme", theme, user["id"])
            set_setting("custom_css", selected_theme["css_text"] if selected_theme else "", user["id"])
            log_event("system_settings_changed", "تعديل إعدادات وهوية النظام", user["id"], None)
            db.commit(); flash("تم حفظ إعدادات الهوية والنظام.", "success")
        elif action == "save_labels":
            for key,value in request.form.items():
                if key.startswith("label_"):
                    set_setting(key, value.strip(), user["id"])
            log_event("ui_labels_changed", "تعديل مسميات واجهة النظام", user["id"], None)
            db.commit(); flash("تم حفظ المسميات القابلة للتهيئة.", "success")
        elif action == "save_theme":
            theme_id = request.form.get("theme_id", type=int)
            if theme_id:
                theme = db.execute("SELECT * FROM system_themes WHERE id=? AND active=1", (theme_id,)).fetchone()
                if theme:
                    set_setting("theme", theme["name"], user["id"])
                    set_setting("custom_css", theme["css_text"], user["id"])
                    log_event("theme_changed", f"تفعيل التصميم: {theme['name']}", user["id"], None)
                    db.commit(); flash("تم تفعيل التصميم.", "success")
        elif action == "create_theme":
            name = request.form.get("name", "").strip(); desc=request.form.get("description", "").strip(); css=request.form.get("css_text", "")
            if not name: flash("اسم التصميم مطلوب.", "danger")
            else:
                try:
                    db.execute("INSERT INTO system_themes(name,description,css_text,created_by,created_at) VALUES(?,?,?,?,?)", (name,desc,css,user["id"],now()))
                    log_event("theme_created", f"إنشاء تصميم: {name}", user["id"], None); db.commit(); flash("تم إنشاء التصميم.", "success")
                except Exception:
                    db.rollback(); flash("تعذر إنشاء التصميم. الاسم قد يكون مستخدمًا.", "danger")
        elif action == "reset_theme":
            set_setting("theme", "رسمي أنيق", user["id"]); set_setting("custom_css", "", user["id"]); log_event("theme_changed", "إعادة التصميم الافتراضي", user["id"], None); db.commit(); flash("تمت إعادة التصميم الافتراضي.", "success")
        return redirect(url_for("main.maintenance_center", section=request.form.get("tab","overview")))
    maintenance = db.execute("SELECT * FROM maintenance_windows WHERE id=1").fetchone()
    pending_resets = db.execute("""SELECT r.*,u.full_name,u.active,s.name station_name FROM password_reset_requests r JOIN users u ON u.id=r.user_id LEFT JOIN stations s ON s.id=u.station_id WHERE r.status='pending' ORDER BY r.created_at DESC""").fetchall()
    sessions = db.execute("""SELECT ls.*,u.username,u.full_name,u.role,s.name station_name FROM login_sessions ls JOIN users u ON u.id=ls.user_id LEFT JOIN stations s ON s.id=u.station_id WHERE ls.active=1 ORDER BY ls.last_seen DESC""").fetchall()
    users = db.execute("""SELECT u.*,s.name station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id ORDER BY CASE u.role WHEN 'super_admin' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, u.full_name""").fetchall()
    themes = db.execute("SELECT * FROM system_themes WHERE active=1 ORDER BY id").fetchall()
    templates = db.execute("SELECT d.*,u.full_name AS uploader FROM document_templates d LEFT JOIN users u ON u.id=d.uploaded_by ORDER BY d.created_at DESC").fetchall()
    stations = db.execute("SELECT * FROM stations ORDER BY active DESC,name").fetchall()
    selected_station_id = request.args.get("station_id", type=int) or (stations[0]["id"] if stations else None)
    selected_month = request.args.get("month", current_month())
    petty_rows = db.execute("SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id", (selected_station_id,selected_month)).fetchall() if selected_station_id else []
    petty_receipts = db.execute("SELECT r.*,u.full_name AS creator_name,v.full_name AS reviewer_name FROM petty_cash_receipts r LEFT JOIN users u ON u.id=r.created_by LEFT JOIN users v ON v.id=r.reviewed_by WHERE r.station_id=? AND r.month_key=? ORDER BY r.created_at DESC",(selected_station_id,selected_month)).fetchall() if selected_station_id else []
    backups = sorted([p for p in Path(current_app.config["BACKUP_DIR"]).glob("*.sqlite3") if p.is_file()], key=lambda x:x.stat().st_mtime, reverse=True)[:20]
    settings = get_settings()
    monitor = {
        "active_sessions": db.execute("SELECT COUNT(*) c FROM login_sessions WHERE active=1").fetchone()["c"],
        "pending": db.execute("SELECT COUNT(*) c FROM operations WHERE status='pending_review'").fetchone()["c"],
        "returned": db.execute("SELECT COUNT(*) c FROM operations WHERE status='returned'").fetchone()["c"],
        "resets": db.execute("SELECT COUNT(*) c FROM password_reset_requests WHERE status='pending'").fetchone()["c"],
        "unread": db.execute("SELECT COUNT(*) c FROM notifications WHERE is_read=0").fetchone()["c"],
    }
    recent = db.execute("""SELECT a.*,u.full_name user_name FROM audit_events a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 25""").fetchall()
    required_health_tables = {"stations","users","operations","petty_cash_items","petty_cash_receipts","month_closings","maintenance_windows","password_reset_requests","login_sessions","system_settings","system_themes","audit_events","operation_actions","corrections"}
    actual_health_tables = {r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    health = {
        "required_tables": required_health_tables.issubset(actual_health_tables),
        "audit_immutable": bool(db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_events_no_update'").fetchone()) and bool(db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name='audit_events_no_delete'").fetchone()),
        "database": Path(current_app.config["DATABASE_PATH"]).exists(),
        "uploads": Path(current_app.config["UPLOAD_DIR"]).exists(),
        "backups": Path(current_app.config["BACKUP_DIR"]).exists(),
        "secret": bool(current_app.config.get("SECRET_KEY")) and current_app.config.get("SECRET_KEY") != "change-this-secret-key-before-production",
        "ip_restrictions": bool(current_app.config.get("ENFORCE_IP_RESTRICTIONS")),
    }
    return render_template(section_map[section], maintenance=maintenance, pending_resets=pending_resets, sessions=sessions, users=users, themes=themes, templates=templates, settings=settings, recent=recent, health=health, stations=stations, selected_station_id=selected_station_id, selected_month=selected_month, petty_rows=petty_rows, petty_receipts=petty_receipts, backups=backups, **monitor)

@bp.post("/maintenance/password-reset/<int:request_id>/<action>")
@require_role("super_admin")
def handle_password_reset(request_id, action):
    if action not in ("approve","reject"): abort(404)
    db=get_db(); row=db.execute("SELECT * FROM password_reset_requests WHERE id=? AND status='pending'", (request_id,)).fetchone()
    if not row: flash("الطلب غير موجود أو تمت معالجته.","warning"); return redirect(url_for("main.maintenance_center",section="passwords"))
    user=get_current_user()
    if action == "approve":
        temp = secrets.token_urlsafe(9)
        db.execute("UPDATE users SET password_hash=?,must_change_password=1,session_token=NULL WHERE id=?", (generate_password_hash(temp),row["user_id"]))
        db.execute("UPDATE login_sessions SET active=0,last_seen=? WHERE user_id=?", (now(),row["user_id"]))
        note=f"تمت إعادة تعيين كلمة المرور. كلمة المرور المؤقتة: {temp}"
        status="approved"
    else:
        note=request.form.get("note", "تم رفض الطلب")
        status="rejected"
    db.execute("UPDATE password_reset_requests SET status=?,handled_by=?,handler_note=?,handled_at=? WHERE id=?", (status,user["id"],note,now(),request_id))
    log_event("password_reset_handled", f"معالجة طلب استعادة كلمة المرور #{request_id}: {status}", user["id"], None)
    db.commit(); flash(note,"success" if action=="approve" else "info")
    return redirect(url_for("main.maintenance_center",section="passwords"))

@bp.post("/maintenance/session/<int:session_id>/terminate")
@require_role("super_admin")
def terminate_session(session_id):
    db=get_db(); row=db.execute("SELECT * FROM login_sessions WHERE id=? AND active=1",(session_id,)).fetchone()
    if row:
        db.execute("UPDATE login_sessions SET active=0,last_seen=? WHERE id=?",(now(),session_id))
        db.execute("UPDATE users SET session_token=NULL WHERE id=? AND session_token=?",(row["user_id"],row["session_token"]))
        log_event("session_terminated",f"إنهاء جلسة المستخدم #{row['user_id']}",get_current_user()["id"],None); db.commit(); flash("تم إنهاء الجلسة.","success")
    return redirect(url_for("main.maintenance_center",section="sessions"))

@bp.post("/maintenance/backup")
@require_role("super_admin")
def maintenance_backup():
    import sqlite3
    src=Path(current_app.config["DATABASE_PATH"]); dest_dir=Path(current_app.config["BACKUP_DIR"]); dest_dir.mkdir(parents=True,exist_ok=True)
    if not src.exists(): flash("قاعدة البيانات غير موجودة.","danger"); return redirect(url_for("main.maintenance_center"))
    dest=dest_dir/f"financial-control-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sqlite3"
    try:
        target=sqlite3.connect(dest)
        get_db().backup(target)
        target.close()
        log_event("database_backup","إنشاء نسخة احتياطية متسقة لقاعدة البيانات",get_current_user()["id"],None); get_db().commit()
        flash(f"تم إنشاء النسخة الاحتياطية: {dest.name}","success")
    except Exception:
        try: target.close()
        except Exception: pass
        if dest.exists(): dest.unlink()
        flash("تعذر إنشاء النسخة الاحتياطية.","danger")
    return redirect(url_for("main.maintenance_center",section="system"))

@bp.get("/maintenance/backup/<path:filename>")
@require_role("super_admin")
def maintenance_backup_download(filename):
    base=Path(current_app.config["BACKUP_DIR"]).resolve(); target=(base/filename).resolve()
    if base not in target.parents or not target.is_file(): abort(404)
    return send_from_directory(base, target.name, as_attachment=True)

@bp.get("/maintenance/diagnostics")
@require_role("super_admin")
def maintenance_diagnostics():
    db=get_db()
    checks={"database":False,"tables":0,"users":0,"stations":0,"operations":0,"petty_cash_items":0,"petty_cash_receipts":0,"audit_events":0,"active_sessions":0,"pending_password_resets":0,"backup_count":0,"upload_files":0,"audit_immutable":False,"required_tables":False,"error":None}
    try:
        checks["database"]=Path(current_app.config["DATABASE_PATH"]).exists()
        checks["tables"]=db.execute("SELECT COUNT(*) c FROM sqlite_master WHERE type='table'").fetchone()["c"]
        checks["users"]=db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        checks["stations"]=db.execute("SELECT COUNT(*) c FROM stations").fetchone()["c"]
        checks["operations"]=db.execute("SELECT COUNT(*) c FROM operations").fetchone()["c"]
        checks["petty_cash_items"]=db.execute("SELECT COUNT(*) c FROM petty_cash_items").fetchone()["c"]
        checks["petty_cash_receipts"]=db.execute("SELECT COUNT(*) c FROM petty_cash_receipts").fetchone()["c"]
        checks["audit_events"]=db.execute("SELECT COUNT(*) c FROM audit_events").fetchone()["c"]
        checks["active_sessions"]=db.execute("SELECT COUNT(*) c FROM login_sessions WHERE active=1").fetchone()["c"]
        checks["pending_password_resets"]=db.execute("SELECT COUNT(*) c FROM password_reset_requests WHERE status='pending'").fetchone()["c"]
        backup_dir=Path(current_app.config["BACKUP_DIR"])
        upload_dir=Path(current_app.config["UPLOAD_DIR"])
        checks["backup_count"]=len([p for p in backup_dir.glob("*.sqlite3") if p.is_file()]) if backup_dir.exists() else 0
        checks["upload_files"]=len([p for p in upload_dir.iterdir() if p.is_file()]) if upload_dir.exists() else 0
        required={"stations","users","operations","petty_cash_items","petty_cash_receipts","month_closings","maintenance_windows","password_reset_requests","login_sessions","system_settings","system_themes","audit_events","operation_actions","corrections"}
        table_names={r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        checks["required_tables"]=required.issubset(table_names)
        trigger_names={r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_events'").fetchall()}
        checks["audit_immutable"]={"audit_events_no_update","audit_events_no_delete"}.issubset(trigger_names)
    except Exception as exc: checks["error"]=str(exc)
    return jsonify(checks)

@bp.post("/maintenance/backup/<path:filename>/restore")
@require_role("super_admin")
def maintenance_backup_restore(filename):
    import sqlite3, shutil
    db=get_db(); base=Path(current_app.config["BACKUP_DIR"]).resolve(); target=(base/secure_filename(filename)).resolve()
    current=Path(current_app.config["DATABASE_PATH"]).resolve()
    if base not in target.parents or not target.is_file() or target.suffix.lower() != ".sqlite3": abort(404)
    if target == current: abort(400)
    # Validate the selected backup before touching the live database.
    try:
        source=sqlite3.connect(target)
        integrity=source.execute("PRAGMA integrity_check").fetchone()[0]
        required={"users","stations","operations","audit_events","maintenance_windows","system_settings","system_themes"}
        tables={r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if integrity != "ok" or not required.issubset(tables):
            source.close(); flash("لا يمكن الاستعادة لأن النسخة غير سليمة أو لا تحتوي على مخطط النظام الكامل.","danger"); return redirect(url_for("main.maintenance_center",section="system"))
        source.close()
    except Exception:
        flash("تعذر فحص النسخة الاحتياطية.","danger"); return redirect(url_for("main.maintenance_center",section="system"))
    # Always create a safety copy immediately before restoration.
    base.mkdir(parents=True,exist_ok=True)
    safety=base/f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sqlite3"
    shutil.copy2(current,safety)
    try:
        source=sqlite3.connect(target)
        source.backup(db)
        source.close()
        db.commit()
        log_event("database_restored",f"استعادة قاعدة البيانات من النسخة {target.name} — نسخة أمان قبل الاستعادة: {safety.name}",get_current_user()["id"],None)
        db.commit()
        flash("تمت استعادة النسخة الاحتياطية بنجاح، وتم الاحتفاظ بنسخة أمان قبل الاستعادة.","success")
    except Exception:
        db.rollback(); flash("فشلت الاستعادة؛ لم يكتمل الإجراء.","danger")
    return redirect(url_for("main.maintenance_center",section="system"))

@bp.get("/maintenance/status")
@require_role("super_admin")
def maintenance_status():
    row=get_db().execute("SELECT * FROM maintenance_windows WHERE id=1").fetchone()
    return jsonify({"enabled":bool(row["enabled"]) if row else False,"title":row["title"] if row else "","message":row["message"] if row else "","started_at":row["started_at"] if row else None,"expected_end_at":row["expected_end_at"] if row else None})

@bp.get("/maintenance/backup/<path:filename>/verify")
@require_role("super_admin")
def maintenance_backup_verify(filename):
    import sqlite3
    base=Path(current_app.config["BACKUP_DIR"]).resolve(); target=(base/secure_filename(filename)).resolve()
    if base not in target.parents or not target.is_file() or target.suffix.lower() != ".sqlite3": abort(404)
    result={"file":target.name,"size":target.stat().st_size,"valid":False,"integrity":""}
    try:
        con=sqlite3.connect(target)
        result["integrity"]=con.execute("PRAGMA integrity_check").fetchone()[0]
        result["valid"]=result["integrity"] == "ok"
        con.close()
    except Exception as exc: result["integrity"]=str(exc)
    log_event("backup_verified",f"فحص سلامة النسخة الاحتياطية {target.name}: {'سليمة' if result['valid'] else 'غير سليمة'}",get_current_user()["id"],None); get_db().commit()
    return jsonify(result)

@bp.route("/settings", methods=["GET", "POST"])
@require_role("manager", "super_admin")
def settings():
    user=get_current_user(); db=get_db()
    if user["role"] == "super_admin": abort(403)
    station=station_for_request(user)
    if request.method=="POST":
        db.execute("UPDATE stations SET name=?,company_name=?,manager_name=?,address=?,phone=? WHERE id=?",(request.form.get("name",""),request.form.get("company_name",""),request.form.get("manager_name",""),request.form.get("address",""),request.form.get("phone",""),station["id"]))
        log_event("station_settings", "تعديل إعدادات المحطة", user["id"], station["id"]); db.commit(); flash("تم حفظ إعدادات المحطة.","success"); return redirect(url_for("main.settings"))
    return render_template("settings.html",station=station)


@bp.route("/password", methods=["GET", "POST"])
@require_login
def change_password():
    user=get_current_user(); db=get_db()
    if request.method=="POST":
        current=request.form.get("current_password","")
        new=request.form.get("new_password","")
        confirm=request.form.get("confirm_password","")
        if not check_password_hash(user["password_hash"],current): flash("كلمة المرور الحالية غير صحيحة.","danger")
        elif len(new)<8: flash("كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف.","danger")
        elif new!=confirm: flash("تأكيد كلمة المرور غير مطابق.","danger")
        else:
            db.execute("UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?",(generate_password_hash(new),user["id"]))
            log_event("password_changed","تغيير كلمة المرور",user["id"],user["station_id"]); db.commit(); flash("تم تغيير كلمة المرور بنجاح.","success"); return redirect(url_for("main.dashboard"))
    return render_template("change_password.html")


@bp.route("/admin/stations", methods=["GET", "POST"])
@require_role("super_admin")
def stations():
    user=get_current_user(); db=get_db()
    if request.method=="POST":
        code=request.form.get("code","").strip().upper(); name=request.form.get("name","").strip()
        if not code or not name: flash("رمز المحطة واسمها إلزاميان.","danger")
        else:
            try:
                cur=db.execute("INSERT INTO stations(code,name,company_name,manager_name,address,phone,active,created_at) VALUES(?,?,?,?,?,?,1,?)",(code,name,request.form.get("company_name",""),request.form.get("manager_name",""),request.form.get("address",""),request.form.get("phone",""),now()))
                sid=cur.lastrowid; ensure_month(sid); log_event("station_created",f"إنشاء محطة {name}",user["id"],sid); db.commit(); flash("تم إنشاء المحطة. تهيئة بنود النثرية وسقوفها تتم من مركز الصيانة بواسطة السوبر أدمن.","success")
            except Exception: db.rollback(); flash("تعذر إنشاء المحطة. تحقق من رمز المحطة.","danger")
    if request.method == "POST" and request.form.get("next") == "maintenance":
        return redirect(url_for("main.maintenance_center",section="stations"))
    rows=db.execute("SELECT * FROM stations ORDER BY active DESC,name").fetchall()
    return render_template("stations.html",rows=rows)


@bp.post("/admin/stations/<int:station_id>/edit")
@require_role("super_admin")
def station_edit(station_id):
    db=get_db(); admin=get_current_user(); row=db.execute("SELECT * FROM stations WHERE id=?",(station_id,)).fetchone()
    if not row: abort(404)
    code=request.form.get("code","").strip().upper(); name=request.form.get("name","").strip()
    if not code or not name: flash("رمز المحطة واسمها إلزاميان.","danger"); return redirect(url_for("main.maintenance_center",section="stations") if request.form.get("next") == "maintenance" else url_for("main.stations"))
    try:
        db.execute("UPDATE stations SET code=?,name=?,company_name=?,manager_name=?,address=?,phone=? WHERE id=?",(code,name,request.form.get("company_name","").strip(),request.form.get("manager_name","").strip(),request.form.get("address","").strip(),request.form.get("phone","").strip(),station_id))
        log_event("station_updated",f"تعديل بيانات المحطة {name}",admin["id"],station_id); db.commit(); flash("تم حفظ بيانات المحطة.","success")
    except Exception:
        db.rollback(); flash("تعذر حفظ بيانات المحطة. رمز المحطة قد يكون مستخدمًا.","danger")
    return redirect(url_for("main.maintenance_center",section="stations") if request.form.get("next") == "maintenance" else url_for("main.stations"))

@bp.post("/admin/stations/<int:station_id>/toggle")
@require_role("super_admin")
def station_toggle(station_id):
    db=get_db(); row=db.execute("SELECT * FROM stations WHERE id=?",(station_id,)).fetchone()
    if not row: abort(404)
    db.execute("UPDATE stations SET active=? WHERE id=?",(0 if row["active"] else 1,station_id)); log_event("station_status",f"تغيير حالة المحطة {row['name']}",get_current_user()["id"],station_id); db.commit(); flash("تم تحديث حالة المحطة.","success"); return redirect(url_for("main.maintenance_center",section="stations") if request.form.get("next") == "maintenance" else url_for("main.stations"))


@bp.route("/users", methods=["GET", "POST"])
@require_role("super_admin")
def users():
    user=get_current_user(); db=get_db()
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password",""); role=request.form.get("role",""); sid=request.form.get("station_id",type=int)
        if role not in ROLE_LABELS or not username or len(password)<8: flash("البيانات غير مكتملة أو كلمة المرور ضعيفة.","danger")
        elif role != "super_admin" and not sid: flash("يجب ربط مدير المحطة أو المتحصل بمحطة.","danger")
        else:
            try:
                db.execute("INSERT INTO users(username,password_hash,full_name,role,station_id,allowed_ip,active,must_change_password,created_at) VALUES(?,?,?,?,?,?,1,1,?)",(username,generate_password_hash(password),request.form.get("full_name",""),role,None if role=="super_admin" else sid,request.form.get("allowed_ip",""),now()))
                log_event("user_created",f"إنشاء المستخدم {username}",user["id"],sid); db.commit(); flash("تم إنشاء المستخدم. سيُطلب منه تغيير كلمة المرور عند أول دخول.","success")
            except Exception: db.rollback(); flash("اسم المستخدم موجود بالفعل أو البيانات غير صالحة.","danger")
    if request.method == "POST" and request.form.get("next") == "maintenance":
        return redirect(url_for("main.maintenance_center",section="users"))
    rows=db.execute("SELECT u.*,s.name AS station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id ORDER BY u.id").fetchall()
    stations_rows=db.execute("SELECT * FROM stations WHERE active=1 ORDER BY name").fetchall()
    return render_template("users.html",rows=rows,stations=stations_rows)


@bp.post("/users/<int:user_id>/edit")
@require_role("super_admin")
def user_edit(user_id):
    db=get_db(); admin=get_current_user(); target=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not target: abort(404)
    role=request.form.get("role",""); sid=request.form.get("station_id",type=int)
    if role not in ROLE_LABELS: flash("الدور غير صالح.","danger"); return redirect(url_for("main.maintenance_center",section="users"))
    if target["id"]==admin["id"] and role!="super_admin": flash("لا يمكن تغيير دور حسابك الإداري من هذه الشاشة.","danger"); return redirect(url_for("main.maintenance_center",section="users"))
    if role!="super_admin" and not db.execute("SELECT id FROM stations WHERE id=? AND active=1",(sid,)).fetchone(): flash("يجب ربط المستخدم بمحطة نشطة.","danger"); return redirect(url_for("main.maintenance_center",section="users"))
    allowed_ip=request.form.get("allowed_ip","").strip()
    if allowed_ip:
        import ipaddress
        try: ipaddress.ip_address(allowed_ip)
        except ValueError: flash("عنوان IP غير صالح.","danger"); return redirect(url_for("main.maintenance_center",section="users"))
    new_sid=None if role=="super_admin" else sid
    try:
        db.execute("UPDATE users SET full_name=?,role=?,station_id=?,allowed_ip=? WHERE id=?",(request.form.get("full_name","").strip(),role,new_sid,allowed_ip,user_id))
        if target["station_id"]!=new_sid: db.execute("UPDATE users SET session_token=NULL WHERE id=?",(user_id,user_id))
        log_event("user_updated",f"تعديل بيانات المستخدم {target['username']}",admin["id"],new_sid); db.commit(); flash("تم حفظ بيانات المستخدم.","success")
    except Exception:
        db.rollback(); flash("تعذر حفظ بيانات المستخدم.","danger")
    return redirect(url_for("main.maintenance_center",section="users"))

@bp.post("/users/<int:user_id>/reset-password")
@require_role("super_admin")
def reset_password(user_id):
    admin=get_current_user(); db=get_db(); target=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not target: abort(404)
    new=request.form.get("new_password","")
    if len(new)<8: flash("كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف.","danger")
    else:
        db.execute("UPDATE users SET password_hash=?,must_change_password=1,session_token=NULL WHERE id=?",(generate_password_hash(new),user_id)); log_event("password_reset",f"إعادة تعيين كلمة مرور المستخدم {target['username']}",admin["id"],target["station_id"]); db.commit(); flash("تمت إعادة تعيين كلمة المرور وسيُطلب من المستخدم تغييرها عند الدخول.","success")
    return redirect(url_for("main.maintenance_center",section="users") if request.form.get("next") == "maintenance" else url_for("main.users"))


@bp.post("/users/<int:user_id>/ip")
@require_role("super_admin")
def user_ip(user_id):
    db=get_db(); row=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not row: abort(404)
    ip=request.form.get("allowed_ip","").strip()
    if ip:
        import ipaddress
        try: ipaddress.ip_address(ip)
        except ValueError: flash("عنوان IP غير صالح.","danger"); return redirect(url_for("main.maintenance_center",section="users")) if request.form.get("next") == "maintenance" else redirect(url_for("main.users"))
    db.execute("UPDATE users SET allowed_ip=? WHERE id=?",(ip,user_id)); log_event("user_ip_changed",f"تعديل IP للمستخدم {row['username']} إلى {ip or 'بدون تقييد'}",get_current_user()["id"],row["station_id"]); db.commit(); flash("تم تحديث IP المستخدم.","success"); return redirect(url_for("main.maintenance_center",section="users")) if request.form.get("next") == "maintenance" else redirect(url_for("main.users"))

@bp.post("/users/<int:user_id>/toggle")
@require_role("super_admin")
def user_toggle(user_id):
    admin=get_current_user(); db=get_db(); target=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not target: abort(404)
    if target["id"]==admin["id"]: flash("لا يمكن تعطيل حسابك من هذه الشاشة.","danger")
    else:
        db.execute("UPDATE users SET active=? WHERE id=?",(0 if target["active"] else 1,user_id)); log_event("user_status",f"تغيير حالة المستخدم {target['username']}",admin["id"],target["station_id"]); db.commit(); flash("تم تحديث حالة المستخدم.","success")
    return redirect(url_for("main.maintenance_center",section="users")) if request.form.get("next") == "maintenance" else redirect(url_for("main.users"))


@bp.post("/users/<int:user_id>/transfer")
@require_role("super_admin")
def transfer_user(user_id):
    admin=get_current_user(); db=get_db(); target=db.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    sid=request.form.get("station_id",type=int)
    if not target or target["role"]=="super_admin" or not sid: abort(400)
    station=db.execute("SELECT id FROM stations WHERE id=? AND active=1",(sid,)).fetchone()
    if not station: abort(400)
    old=target["station_id"]; db.execute("UPDATE users SET station_id=?,session_token=NULL WHERE id=?",(sid,user_id)); log_event("user_transfer",f"نقل المستخدم {target['username']} من محطة {old} إلى {sid}",admin["id"],sid); db.commit(); flash("تم نقل المستخدم وتسجيل العملية.","success"); return redirect(url_for("main.maintenance_center",section="users") if request.form.get("next") == "maintenance" else url_for("main.users"))


@bp.route("/templates", methods=["GET", "POST"])
@require_login
def document_templates():
    user=get_current_user(); db=get_db()
    if user["role"] == "super_admin" and request.method=="POST":
        file=request.files.get("file")
        if not file or not file.filename or not allowed_file(file.filename,{"pdf"}): flash("يجب رفع ملف PDF فقط.","danger")
        else:
            path=save_attachment(file,{"pdf"})
            if path:
                db.execute("INSERT INTO document_templates(title,description,file_path,active,uploaded_by,created_at) VALUES(?,?,?,1,?,?)",(request.form.get("title","استمارة رسمية"),request.form.get("description",""),path,user["id"],now())); log_event("template_uploaded",f"إضافة استمارة {request.form.get('title','')}",user["id"],None); db.commit(); flash("تمت إضافة الاستمارة المركزية.","success")
    if request.method == "POST" and request.form.get("next") == "maintenance":
        return redirect(url_for("main.maintenance_center",section="templates"))
    rows=db.execute("SELECT d.*,u.full_name AS uploader FROM document_templates d LEFT JOIN users u ON u.id=d.uploaded_by WHERE d.active=1 ORDER BY d.created_at DESC").fetchall()
    return render_template("document_templates.html",rows=rows)


@bp.post("/templates/<int:template_id>/toggle")
@require_role("super_admin")
def template_toggle(template_id):
    db=get_db(); row=db.execute("SELECT * FROM document_templates WHERE id=?",(template_id,)).fetchone()
    if not row: abort(404)
    db.execute("UPDATE document_templates SET active=? WHERE id=?",(0 if row["active"] else 1,template_id)); log_event("template_status",f"تغيير حالة الاستمارة #{template_id}",get_current_user()["id"],None); db.commit(); flash("تم تحديث حالة الاستمارة.","success"); return redirect(url_for("main.maintenance_center",section="templates") if request.form.get("next") == "maintenance" else url_for("main.document_templates"))


@bp.route("/template-files/<path:filename>")
@require_login
def template_files(filename):
    return send_from_directory(current_app.config["UPLOAD_DIR"],filename,as_attachment=False)


@bp.get("/notifications")
@require_login
def notifications():
    user=get_current_user(); db=get_db()
    rows=db.execute("SELECT * FROM notifications WHERE user_id=? OR (user_id IS NULL AND (role_target IS NULL OR role_target=?) AND (station_id IS NULL OR station_id=?)) ORDER BY id DESC LIMIT 100",(user["id"],user["role"],user["station_id"])).fetchall()
    return render_template("notifications.html", rows=rows)

@bp.post("/notifications/<int:notification_id>/read")
@require_login
def notification_read(notification_id):
    user=get_current_user(); db=get_db()
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND (user_id=? OR (user_id IS NULL AND (role_target IS NULL OR role_target=?) AND (station_id IS NULL OR station_id=?)))",(notification_id,user["id"],user["role"],user["station_id"]))
    db.commit(); return redirect(request.form.get("next") or url_for("main.notifications"))

@bp.post("/notifications/read-all")
@require_login
def notifications_read_all():
    user=get_current_user(); db=get_db()
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=? OR (user_id IS NULL AND (role_target IS NULL OR role_target=?) AND (station_id IS NULL OR station_id=?))",(user["id"],user["role"],user["station_id"]))
    db.commit(); return redirect(url_for("main.notifications"))

@bp.get("/search")
@require_login
def global_search():
    user=get_current_user(); q=request.args.get("q","").strip()
    results=[]
    if q:
        db=get_db(); where,params=operation_query_scope(user)
        rows=db.execute(f"SELECT o.*,s.name station_name FROM operations o JOIN stations s ON s.id=o.station_id WHERE {where} AND (o.op_no LIKE ? OR o.title LIKE ? OR o.category LIKE ? OR o.description LIKE ?) ORDER BY o.id DESC LIMIT 50", [*params]+[f"%{q}%"]*4).fetchall()
        results=[{"kind":"operation","title":r["op_no"]+" — "+r["title"],"meta":TYPE_LABELS.get(r["op_type"],r["op_type"])+" • "+r["station_name"],"link":url_for("main.operation_detail",operation_id=r["id"])} for r in rows]
        stations=db.execute("SELECT id,name,code FROM stations WHERE name LIKE ? OR code LIKE ? LIMIT 20",(f"%{q}%",f"%{q}%")).fetchall() if user["role"]=="super_admin" else []
        results += [{"kind":"station","title":r["name"],"meta":r["code"],"link":url_for("main.maintenance_center",section="stations",station_id=r["id"])} for r in stations]
        if user["role"]=="super_admin":
            users=db.execute("SELECT id,username,full_name FROM users WHERE username LIKE ? OR full_name LIKE ? LIMIT 20",(f"%{q}%",f"%{q}%")).fetchall()
            results += [{"kind":"user","title":r["full_name"] or r["username"],"meta":r["username"],"link":url_for("main.maintenance_center",section="users")} for r in users]
        docs=db.execute("SELECT id,title,description FROM document_templates WHERE active=1 AND (title LIKE ? OR description LIKE ?) LIMIT 20",(f"%{q}%",f"%{q}%")).fetchall()
        results += [{"kind":"document","title":r["title"],"meta":r["description"] or "نموذج رسمي","link":url_for("main.document_templates")} for r in docs]
    return render_template("global_search.html", q=q, results=results)

HELP_CATALOG = {
    "dashboard": {"title":"لوحة التحكم", "icon":"⌂", "summary":"ابدأ من هنا لمتابعة وضع المحطة والعمليات والتنبيهات.", "steps":["راجع البطاقات والمؤشرات المالية.","افتح قسم «يحتاج انتباهك الآن» لمعرفة ما يتطلب إجراءً.","استخدم النشاط الأخير للوصول إلى تفاصيل العملية."], "next":"إذا وجدت عملية تحتاج إجراءً، افتحها وانتقل إلى الخطوة التالية الظاهرة في مسار العملية."},
    "approval": {"title":"طلبات التصديق", "icon":"✓", "summary":"أنشئ طلب التصديق وأرسله للمراجعة مع المستند المطلوب.", "steps":["أدخل بيانات العملية والمبلغ والبند.","أرفق المستند الرسمي المطلوب.","نفذ فحص الجاهزية قبل الإرسال إن كان متاحًا.","أرسل العملية للمراجعة وانتظر قرار المدير."], "next":"بعد الاعتماد تصبح العملية مقفلة؛ وأي تصحيح لاحق يتم بإجراء تصحيحي مسجل."},
    "petty_cash": {"title":"النثرية", "icon":"▣", "summary":"تابع السقف الشهري، المصروف المعتمد، والمتبقي لكل بند.", "steps":["اختر الشهر النشط.","راجع سقف كل بند والمصروف المعتمد.","تأكد من الرصيد الفعلي عند تنفيذ المصروف.","استخدم مسار تغذية النثرية عند تسجيل الاستلام."], "next":"إذا كان البند قريبًا من النفاد، لا تتجاوز سقفه؛ راجع التمويل أو المسار المعتمد قبل إنشاء مصروف جديد."},
    "due": {"title":"المستحقات والسلف", "icon":"◷", "summary":"تابع المستحقات والسلف والتسويات حتى لا تتوقف دورة الإغلاق.", "steps":["افتح العملية لمعرفة المبلغ والحالة.","راجع المبلغ غير المسوى.","عند الإرجاع سجّل إثبات التسوية والملاحظة المطلوبة.","تابع العملية حتى تصبح مسواة."], "next":"قبل إغلاق الشهر تأكد من عدم وجود مستحقات غير مسواة."},
    "documents": {"title":"النماذج والمستندات", "icon":"▤", "summary":"استخدم النموذج الرسمي ثم اربط المستند بالعملية.", "steps":["اختر النموذج الرسمي المناسب.","افتحه أو اطبعه.","وقّع واختم المستند حسب الإجراء الداخلي.","صوّر المستند بوضوح وارفعه وربطه بالعملية."], "next":"تأكد أن المرفق قابل للقراءة وأنه مرتبط بالعملية الصحيحة قبل إرسالها."},
    "operation": {"title":"دورة العملية", "icon":"↻", "summary":"كل عملية تمر بمراحل واضحة من الإنشاء إلى الإغلاق.", "steps":["الإنشاء وإدخال البيانات.","تجهيز المستند الرسمي.","المراجعة والاعتماد أو الإرجاع.","التنفيذ والتسوية عند الحاجة.","الإغلاق بعد اكتمال المتطلبات."], "next":"استخدم «استكمال العملية» عندما تعود إلى عملية متوقفة، واتبع المرحلة الحالية بدل إعادة إنشاء العملية."},
    "security": {"title":"الأمان وكلمات المرور", "icon":"⌁", "summary":"اتبع قواعد الدخول الآمن ولا تشارك بيانات الحساب.", "steps":["استخدم بيانات حسابك فقط.","غيّر كلمة المرور عند طلب النظام.","إذا نسيت كلمة المرور استخدم طلب الاستعادة.","لا تشارك كلمة المرور المؤقتة مع أي شخص."], "next":"في حالة فقدان الوصول، ارفع طلب الاستعادة عبر شاشة الدخول واتبع الإجراء الذي يحدده النظام."},
    "notifications": {"title":"الإشعارات والتنبيهات", "icon":"🔔", "summary":"مركز واحد لمعرفة ما استجد وما يحتاج إجراءً.", "steps":["افتح مركز الإشعارات من رمز الجرس.","راجع الإشعارات غير المقروءة.","افتح الرابط المرفق بالإشعار إن وجد.","علّم الإشعار كمقروء بعد مراجعته."], "next":"لا تعتمد على الإشعار وحده؛ افتح العملية نفسها للتأكد من حالتها الحالية."},
    "search": {"title":"البحث الشامل", "icon":"⌕", "summary":"ابحث عن العمليات والمعلومات التي يسمح لك دورك بالوصول إليها.", "steps":["اكتب رقم العملية أو العنوان أو البند أو كلمة مرتبطة بها.","راجع نوع النتيجة والمحطة.","افتح النتيجة للوصول إلى التفاصيل."], "next":"نتائج البحث تخضع لصلاحيات الحساب ولا تعرض بيانات محطة غير مصرح لك بها."},
    "maintenance": {"title":"مركز الصيانة والتشغيل", "icon":"⚙", "summary":"مساحة الإدارة التقنية للسوبر أدمن لإدارة النظام ومراقبته.", "steps":["اختر القسم التقني المطلوب.","نفذ الإجراء الإداري المطلوب.","راجع النتيجة الفعلية بعد الحفظ.","تذكر أن الإجراءات الحساسة تسجل في التدقيق."], "next":"لا تحاول معالجة مشكلة تشغيلية بتغيير البيانات المالية مباشرة؛ استخدم الوظيفة التقنية المناسبة وسجل التدقيق."},
    "logs": {"title":"سجل الحركة والتدقيق", "icon":"≡", "summary":"السجل هو المرجع الزمني لإجراءات النظام الحساسة.", "steps":["ابحث عن الإجراء أو العملية.","راجع المستخدم والوقت وIP والتفاصيل.","قارن الحدث مع حالة العملية الحالية."], "next":"السجل للمتابعة والتدقيق وليس للتعديل أو الحذف."},
}

@bp.get("/help")
@require_login
def help_center():
    topics = []
    db = get_db()
    rows = db.execute("SELECT topic_key,title,body FROM help_topics ORDER BY id").fetchall()
    db_topics = {r["topic_key"]: r for r in rows}
    for key, item in HELP_CATALOG.items():
        row = db_topics.get(key)
        topics.append({"key":key,"title":item["title"],"icon":item["icon"],"summary":item["summary"],"body":row["body"] if row else ""})
    for row in rows:
        if row["topic_key"] not in HELP_CATALOG:
            topics.append({"key":row["topic_key"],"title":row["title"],"icon":"?","summary":row["body"],"body":row["body"]})
    return render_template("help_center.html", topics=topics)

@bp.get("/help/<topic>")
@require_login
def contextual_help(topic):
    item = HELP_CATALOG.get(topic)
    row = get_db().execute("SELECT * FROM help_topics WHERE topic_key=?",(topic,)).fetchone()
    if not item and not row: abort(404)
    if item:
        data = dict(item)
        data["key"] = topic
        data["body"] = row["body"] if row else item["summary"]
    else:
        data = {"key":row["topic_key"],"title":row["title"],"icon":"?","summary":row["body"],"body":row["body"],"steps":[],"next":""}
    return render_template("help_topic.html", topic=data)

@bp.post("/operation/<int:operation_id>/preflight")
@require_login
def operation_preflight(operation_id):
    user=get_current_user(); db=get_db(); op=db.execute("SELECT * FROM operations WHERE id=?",(operation_id,)).fetchone()
    if not op: abort(404)
    require_operation_access(op,user)
    checks=[]
    checks.append((bool(op.title),"بيانات العملية"))
    checks.append((op.amount>0,"المبلغ"))
    checks.append((bool(op.attachment_path),"المرفق الرسمي"))
    if op.op_type=='approval': checks.append((bool(op.category),"بند النثرية")); checks.append(((category_remaining(op["station_id"],current_month(),op["category"],op["id"]) or 0)>=op["amount"],"المتاح في البند"))
    return jsonify({"ready":all(x[0] for x in checks),"checks":[{"ok":x[0],"label":x[1]} for x in checks]})

@bp.get("/operation/<int:operation_id>/bundle")
@require_login
def operation_bundle(operation_id):
    user=get_current_user(); db=get_db(); op=db.execute("SELECT o.*,s.name station_name FROM operations o JOIN stations s ON s.id=o.station_id WHERE o.id=?",(operation_id,)).fetchone()
    if not op: abort(404)
    require_operation_access(op,user)
    actions=db.execute("SELECT * FROM operation_actions WHERE operation_id=? ORDER BY created_at",(operation_id,)).fetchall()
    corrections=db.execute("SELECT * FROM corrections WHERE operation_id=? ORDER BY created_at",(operation_id,)).fetchall()
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('operation.txt', f"رقم العملية: {op['op_no']}\nالنوع: {TYPE_LABELS.get(op['op_type'],op['op_type'])}\nالعنوان: {op['title']}\nالمحطة: {op['station_name']}\nالمبلغ: {op['amount']}\nالحالة: {STATUS_LABELS.get(op['status'],op['status'])}\nالوصف: {op['description'] or ''}\n")
        z.writestr('timeline.txt','\n'.join(f"{a['created_at']} | {a['action']} | {a['old_status'] or '-'} -> {a['new_status'] or '-'} | {a['note'] or ''}" for a in actions) or 'لا يوجد سجل حركة')
        z.writestr('corrections.txt','\n'.join(f"{c['created_at']} | {c['field_name']} | {c['old_value']} -> {c['new_value']} | {c['reason']}" for c in corrections) or 'لا توجد إجراءات تصحيحية')
        if op['attachment_path']:
            fp=Path(current_app.config['UPLOAD_DIR'])/op['attachment_path']
            if fp.exists(): z.write(fp, 'attachments/'+fp.name)
    out.seek(0); return current_app.response_class(out.getvalue(),mimetype='application/zip',headers={'Content-Disposition':f'attachment; filename=operation-{op["op_no"]}.zip'})

@bp.get("/maintenance/operations-monitor")
@require_role("super_admin")
def maintenance_operations_monitor():
    db=get_db(); stations=db.execute("SELECT * FROM stations ORDER BY name").fetchall()
    active_sessions=db.execute("SELECT COUNT(*) c FROM login_sessions WHERE active=1").fetchone()["c"]
    pending=db.execute("SELECT COUNT(*) c FROM operations WHERE status='pending_review'").fetchone()["c"]
    returned=db.execute("SELECT COUNT(*) c FROM operations WHERE status='returned'").fetchone()["c"]
    resets=db.execute("SELECT COUNT(*) c FROM password_reset_requests WHERE status='pending'").fetchone()["c"]
    unread=db.execute("SELECT COUNT(*) c FROM notifications WHERE is_read=0").fetchone()["c"]
    return render_template("maintenance_monitor.html",stations=stations,active_sessions=active_sessions,pending=pending,returned=returned,resets=resets,unread=unread)

@bp.route("/logs")
@require_role("manager", "super_admin")
def logs():
    user=get_current_user(); db=get_db()
    if user["role"]=="super_admin":
        rows=db.execute("""SELECT a.*,u.full_name AS user_name,s.name AS station_name FROM audit_events a
            LEFT JOIN users u ON u.id=a.user_id LEFT JOIN stations s ON s.id=a.station_id ORDER BY a.created_at DESC LIMIT 500""").fetchall()
    else:
        rows=db.execute("""SELECT a.*,u.full_name AS user_name,s.name AS station_name FROM audit_events a
            LEFT JOIN users u ON u.id=a.user_id LEFT JOIN stations s ON s.id=a.station_id WHERE a.station_id=? ORDER BY a.created_at DESC LIMIT 300""",(user["station_id"],)).fetchall()
    return render_template("logs.html",rows=rows)
