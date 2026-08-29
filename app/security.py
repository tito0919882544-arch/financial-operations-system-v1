import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import session, redirect, url_for, flash, request, current_app, abort
from werkzeug.security import check_password_hash
from .db import get_db, now


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute(
        """SELECT u.*, s.name AS station_name, s.code AS station_code
           FROM users u LEFT JOIN stations s ON s.id = u.station_id
           WHERE u.id=? AND u.active=1""",
        (user_id,),
    ).fetchone()


def login_user(user):
    token = secrets.token_urlsafe(32)
    session.clear()
    session["user_id"] = user["id"]
    session["session_token"] = token
    session["last_seen"] = now()
    session["csrf_token"] = secrets.token_urlsafe(32)
    get_db().execute("UPDATE users SET session_token=? WHERE id=?", (token, user["id"]))
    get_db().commit()


def logout_user():
    user_id = session.get("user_id")
    if user_id:
        get_db().execute("UPDATE users SET session_token=NULL WHERE id=?", (user_id,))
        get_db().commit()
    session.clear()


def verify_login(username, password):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("main.login"))

        # انتهاء الجلسة بسبب الخمول
        last_seen = session.get("last_seen")
        if last_seen:
            try:
                last_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_dt > timedelta(minutes=current_app.config["SESSION_TIMEOUT_MINUTES"]):
                    flash("انتهت الجلسة بسبب عدم النشاط. سجل الدخول مرة أخرى.", "warning")
                    logout_user()
                    return redirect(url_for("main.login"))
            except ValueError:
                pass
        session["last_seen"] = now()

        # جلسة واحدة لكل مستخدم
        if user["session_token"] and session.get("session_token") != user["session_token"]:
            flash("تم فتح جلسة أخرى لهذا المستخدم. سجل الدخول من جديد.", "warning")
            session.clear()
            return redirect(url_for("main.login"))

        # تقييد IP عند تفعيله من config.py
        if current_app.config.get("ENFORCE_IP_RESTRICTIONS") and user["role"] != "super_admin":
            allowed_ip = (user["allowed_ip"] or "").strip()
            if allowed_ip and request.remote_addr != allowed_ip:
                abort(403)

        return view(*args, **kwargs)
    return wrapped


def require_role(*roles):
    def decorator(view):
        @wraps(view)
        @require_login
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf():
    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(400, description="CSRF token invalid")
