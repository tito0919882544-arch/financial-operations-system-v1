from pathlib import Path
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    current_app, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

from .db import get_db, now
from .security import (
    get_current_user, verify_login, login_user, logout_user,
    require_login, require_role, csrf_token, validate_csrf
)
from .services import (
    TYPE_LABELS, STATUS_LABELS, STATUS_CLASSES, next_operation_number,
    log_action, station_for_user, operation_query_scope, current_month
)

bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject_globals():
    return {
        "current_user": get_current_user(),
        "csrf_token": csrf_token,
        "TYPE_LABELS": TYPE_LABELS,
        "STATUS_LABELS": STATUS_LABELS,
        "STATUS_CLASSES": STATUS_CLASSES,
    }


@bp.before_app_request
def protect_post_requests():
    if request.endpoint == "main.login":
        return
    validate_csrf()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


def save_attachment(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        flash("نوع المرفق غير مسموح. المسموح: PDF / JPG / PNG", "danger")
        return None
    filename = secure_filename(file_storage.filename)
    # secure_filename قد يحذف العربية، لذلك نضيف رقم وقت لحفظ فريد
    final_name = f"{now().replace(':','').replace(' ','_')}_{filename or 'attachment'}"
    path = Path(current_app.config["UPLOAD_DIR"]) / final_name
    file_storage.save(path)
    return final_name


def require_operation_access(op, user):
    if user["role"] == "super_admin":
        return
    if op["station_id"] != user["station_id"]:
        abort(403)


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


@bp.route("/logout")
def logout():
    logout_user()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("main.login"))


@bp.route("/")
@require_login
def dashboard():
    user = get_current_user()
    db = get_db()
    where, params = operation_query_scope(user)

    cards = {}
    for op_type in ["revenue", "deposit", "approval"]:
        row = db.execute(
            f"SELECT COUNT(*) c, COALESCE(SUM(amount),0) total FROM operations o WHERE {where} AND op_type=? AND status='approved'",
            (*params, op_type),
        ).fetchone()
        cards[op_type] = row

    pending = db.execute(
        f"SELECT COUNT(*) c FROM operations o WHERE {where} AND status='pending_review'",
        params,
    ).fetchone()["c"]
    returned = db.execute(
        f"SELECT COUNT(*) c FROM operations o WHERE {where} AND status='returned'",
        params,
    ).fetchone()["c"]

    recent = db.execute(
        f"""SELECT o.*, u.full_name AS creator_name FROM operations o
             LEFT JOIN users u ON u.id=o.created_by
             WHERE {where}
             ORDER BY o.created_at DESC LIMIT 8""",
        params,
    ).fetchall()

    month_key = current_month()
    station = station_for_user(user)
    petty = db.execute(
        "SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id",
        (station["id"], month_key),
    ).fetchall()
    petty_total = sum([p["allocated_amount"] for p in petty]) if petty else 0
    petty_spent = sum([p["spent_amount"] for p in petty]) if petty else 0
    near_limit = [p for p in petty if p["allocated_amount"] > 0 and (p["allocated_amount"] - p["spent_amount"]) <= p["allocated_amount"] * 0.15]
    closing = db.execute("SELECT * FROM month_closings WHERE station_id=? AND month_key=?", (station["id"], month_key)).fetchone()

    alerts = []
    if pending:
        alerts.append(("warning", f"توجد {pending} عملية بانتظار اعتماد المدير."))
    if returned:
        alerts.append(("info", f"توجد {returned} عملية مرتجعة للتصحيح."))
    if near_limit:
        alerts.append(("danger", f"{len(near_limit)} بند من النثرية اقترب من النفاد."))
    if not closing or closing["status"] != "closed":
        alerts.append(("warning", "الشهر الحالي لم يتم قفله بعد."))

    return render_template(
        "dashboard.html",
        cards=cards,
        pending=pending,
        returned=returned,
        recent=recent,
        petty_total=petty_total,
        petty_spent=petty_spent,
        alerts=alerts,
        month_key=month_key,
    )


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
    sql = f"""SELECT o.*, u.full_name AS creator_name, r.full_name AS reviewer_name
              FROM operations o
              LEFT JOIN users u ON u.id=o.created_by
              LEFT JOIN users r ON r.id=o.reviewed_by
              WHERE {where} AND o.op_type=?"""
    values = [*params, op_type]
    if status:
        sql += " AND o.status=?"
        values.append(status)
    if q:
        sql += " AND (o.op_no LIKE ? OR o.title LIKE ? OR o.category LIKE ?)"
        values.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    sql += " ORDER BY o.created_at DESC"
    rows = db.execute(sql, values).fetchall()
    return render_template("operations_list.html", rows=rows, op_type=op_type, status=status, q=q)


@bp.route("/operations/<op_type>/new", methods=["GET", "POST"])
@require_login
def operation_new(op_type):
    if op_type not in ("revenue", "deposit", "approval", "expense", "due"):
        abort(404)
    user = get_current_user()
    if user["role"] not in ("collector", "manager", "super_admin"):
        abort(403)
    station = station_for_user(user)
    if request.method == "POST":
        amount = float(request.form.get("amount") or 0)
        attachment = save_attachment(request.files.get("attachment"))
        op_no = next_operation_number(station["id"], op_type)
        title = request.form.get("title") or TYPE_LABELS[op_type]
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        allocated_amount = request.form.get("allocated_amount") or None
        db = get_db()
        cur = db.execute(
            """INSERT INTO operations(station_id, op_no, op_type, title, category, amount, allocated_amount,
                       description, attachment_path, status, locked, created_by, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,'pending_review',0,?,?,?)""",
            (station["id"], op_no, op_type, title, category, amount, allocated_amount, description, attachment, user["id"], now(), now()),
        )
        operation_id = cur.lastrowid
        log_action(operation_id, "إنشاء عملية", None, "pending_review", "تم إنشاء العملية وإرسالها للمراجعة.", user["id"])
        db.commit()
        flash(f"تم إنشاء العملية بالرقم {op_no} وهي الآن قيد مراجعة المدير.", "success")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    return render_template("operation_form.html", op_type=op_type, op=None)


@bp.route("/operation/<int:operation_id>")
@require_login
def operation_detail(operation_id):
    user = get_current_user()
    db = get_db()
    op = db.execute(
        """SELECT o.*, s.name AS station_name, s.company_name, s.manager_name,
                  u.full_name AS creator_name, r.full_name AS reviewer_name
           FROM operations o
           JOIN stations s ON s.id=o.station_id
           LEFT JOIN users u ON u.id=o.created_by
           LEFT JOIN users r ON r.id=o.reviewed_by
           WHERE o.id=?""",
        (operation_id,),
    ).fetchone()
    if not op:
        abort(404)
    require_operation_access(op, user)
    actions = db.execute(
        """SELECT a.*, u.full_name AS user_name FROM operation_actions a
           LEFT JOIN users u ON u.id=a.user_id
           WHERE a.operation_id=? ORDER BY a.created_at DESC""",
        (operation_id,),
    ).fetchall()
    corrections = db.execute(
        """SELECT c.*, u.full_name AS user_name FROM corrections c
           LEFT JOIN users u ON u.id=c.created_by
           WHERE c.operation_id=? ORDER BY c.created_at DESC""",
        (operation_id,),
    ).fetchall()
    return render_template("operation_detail.html", op=op, actions=actions, corrections=corrections)


@bp.route("/operation/<int:operation_id>/edit", methods=["GET", "POST"])
@require_login
def operation_edit(operation_id):
    user = get_current_user()
    db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op:
        abort(404)
    require_operation_access(op, user)
    if op["locked"] or op["status"] == "approved":
        flash("لا يمكن تعديل عملية معتمدة. استخدم إجراء تصحيحي مسجل.", "danger")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    if user["role"] == "collector" and op["created_by"] != user["id"]:
        abort(403)
    if request.method == "POST":
        old_status = op["status"]
        attachment = op["attachment_path"]
        new_file = request.files.get("attachment")
        if new_file and new_file.filename:
            attachment = save_attachment(new_file) or attachment
        db.execute(
            """UPDATE operations SET title=?, category=?, amount=?, allocated_amount=?, description=?, attachment_path=?, status='pending_review', updated_at=?
               WHERE id=?""",
            (
                request.form.get("title") or TYPE_LABELS[op["op_type"]],
                request.form.get("category", ""),
                float(request.form.get("amount") or 0),
                request.form.get("allocated_amount") or None,
                request.form.get("description", ""),
                attachment,
                now(),
                operation_id,
            ),
        )
        log_action(operation_id, "تعديل وإعادة إرسال", old_status, "pending_review", "تم تعديل العملية وإعادتها للمراجعة.", user["id"])
        db.commit()
        flash("تم تعديل العملية وإعادتها لقائمة المراجعة.", "success")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    return render_template("operation_form.html", op_type=op["op_type"], op=op)


@bp.post("/operation/<int:operation_id>/review/<action>")
@require_role("manager", "super_admin")
def operation_review(operation_id, action):
    if action not in ("approve", "return", "reject"):
        abort(404)
    user = get_current_user()
    db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op:
        abort(404)
    require_operation_access(op, user)
    if op["locked"] or op["status"] == "approved":
        flash("هذه العملية معتمدة ومقفلة بالفعل.", "warning")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    note = request.form.get("manager_note", "").strip()
    mapping = {
        "approve": ("approved", "اعتماد"),
        "return": ("returned", "إرجاع للتصحيح"),
        "reject": ("rejected", "رفض"),
    }
    new_status, action_label = mapping[action]
    locked = 1 if new_status == "approved" else 0
    db.execute(
        """UPDATE operations SET status=?, locked=?, reviewed_by=?, reviewed_at=?, manager_note=?, updated_at=? WHERE id=?""",
        (new_status, locked, user["id"], now(), note, now(), operation_id),
    )
    log_action(operation_id, action_label, op["status"], new_status, note, user["id"])
    db.commit()
    flash(f"تم تنفيذ إجراء: {action_label}.", "success")
    return redirect(url_for("main.operation_detail", operation_id=operation_id))


@bp.post("/operation/<int:operation_id>/correct")
@require_role("manager", "super_admin")
def operation_correct(operation_id):
    user = get_current_user()
    db = get_db()
    op = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
    if not op:
        abort(404)
    require_operation_access(op, user)
    if op["status"] != "approved":
        flash("الإجراء التصحيحي مخصص للعمليات المعتمدة فقط.", "warning")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    reason = request.form.get("reason", "").strip()
    if not reason:
        flash("سبب التصحيح إلزامي.", "danger")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    fields = {
        "amount": request.form.get("amount"),
        "category": request.form.get("category"),
        "description": request.form.get("description"),
    }
    updates = []
    for field, new_value in fields.items():
        if new_value is None or str(new_value).strip() == "":
            continue
        old_value = str(op[field] or "")
        value_to_store = float(new_value) if field == "amount" else new_value
        if str(value_to_store) != old_value:
            updates.append((field, old_value, str(value_to_store), value_to_store))
    if not updates:
        flash("لا توجد قيمة جديدة للتصحيح.", "info")
        return redirect(url_for("main.operation_detail", operation_id=operation_id))
    for field, old_value, new_value, store_value in updates:
        db.execute(
            """INSERT INTO corrections(operation_id, field_name, old_value, new_value, reason, created_by, ip_address, created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (operation_id, field, old_value, new_value, reason, user["id"], request.remote_addr, now()),
        )
        db.execute(f"UPDATE operations SET {field}=?, updated_at=? WHERE id=?", (store_value, now(), operation_id))
    log_action(operation_id, "إجراء تصحيحي", "approved", "approved", reason, user["id"])
    db.commit()
    flash("تم تنفيذ الإجراء التصحيحي وتسجيله في سجل التدقيق.", "success")
    return redirect(url_for("main.operation_detail", operation_id=operation_id))


@bp.route("/operation/<int:operation_id>/print")
@require_login
def operation_print(operation_id):
    user = get_current_user()
    db = get_db()
    op = db.execute(
        """SELECT o.*, s.name AS station_name, s.company_name, s.manager_name, s.address, s.phone,
                  u.full_name AS creator_name, r.full_name AS reviewer_name
           FROM operations o
           JOIN stations s ON s.id=o.station_id
           LEFT JOIN users u ON u.id=o.created_by
           LEFT JOIN users r ON r.id=o.reviewed_by
           WHERE o.id=?""",
        (operation_id,),
    ).fetchone()
    if not op:
        abort(404)
    require_operation_access(op, user)
    return render_template("print_operation.html", op=op)


@bp.route("/uploads/<path:filename>")
@require_login
def uploads(filename):
    return send_from_directory(current_app.config["UPLOAD_DIR"], filename)


@bp.route("/petty-cash")
@require_login
def petty_cash():
    user = get_current_user()
    station = station_for_user(user)
    month_key = request.args.get("month") or current_month()
    rows = get_db().execute(
        "SELECT * FROM petty_cash_items WHERE station_id=? AND month_key=? ORDER BY id",
        (station["id"], month_key),
    ).fetchall()
    return render_template("petty_cash.html", rows=rows, month_key=month_key)


@bp.route("/settings", methods=["GET", "POST"])
@require_role("manager", "super_admin")
def settings():
    user = get_current_user()
    db = get_db()
    station = station_for_user(user)
    if request.method == "POST":
        db.execute(
            """UPDATE stations SET name=?, company_name=?, manager_name=?, address=?, phone=? WHERE id=?""",
            (
                request.form.get("name", ""),
                request.form.get("company_name", ""),
                request.form.get("manager_name", ""),
                request.form.get("address", ""),
                request.form.get("phone", ""),
                station["id"],
            ),
        )
        db.commit()
        flash("تم حفظ إعدادات المحطة.", "success")
        return redirect(url_for("main.settings"))
    return render_template("settings.html", station=station)


@bp.route("/users", methods=["GET", "POST"])
@require_role("super_admin")
def users():
    db = get_db()
    if request.method == "POST":
        db.execute(
            """INSERT INTO users(username,password_hash,full_name,role,station_id,allowed_ip,active,created_at)
               VALUES(?,?,?,?,?,?,1,?)""",
            (
                request.form.get("username"),
                generate_password_hash(request.form.get("password") or "123456"),
                request.form.get("full_name"),
                request.form.get("role"),
                request.form.get("station_id") or None,
                request.form.get("allowed_ip", ""),
                now(),
            ),
        )
        db.commit()
        flash("تم إنشاء المستخدم.", "success")
        return redirect(url_for("main.users"))
    rows = db.execute(
        """SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id ORDER BY u.id"""
    ).fetchall()
    stations = db.execute("SELECT * FROM stations WHERE active=1 ORDER BY name").fetchall()
    return render_template("users.html", rows=rows, stations=stations)


@bp.route("/logs")
@require_role("manager", "super_admin")
def logs():
    user = get_current_user()
    db = get_db()
    if user["role"] == "super_admin":
        rows = db.execute(
            """SELECT a.*, o.op_no, o.op_type, u.full_name AS user_name
                 FROM operation_actions a
                 LEFT JOIN operations o ON o.id=a.operation_id
                 LEFT JOIN users u ON u.id=a.user_id
                 ORDER BY a.created_at DESC LIMIT 300"""
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT a.*, o.op_no, o.op_type, u.full_name AS user_name
                 FROM operation_actions a
                 LEFT JOIN operations o ON o.id=a.operation_id
                 LEFT JOIN users u ON u.id=a.user_id
                 WHERE o.station_id=?
                 ORDER BY a.created_at DESC LIMIT 300""",
            (user["station_id"],),
        ).fetchall()
    return render_template("logs.html", rows=rows)
