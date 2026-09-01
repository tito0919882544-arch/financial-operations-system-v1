import secrets
import ipaddress
from functools import wraps
from datetime import datetime, timedelta
from flask import session, redirect, url_for, flash, request, current_app, abort
from werkzeug.security import check_password_hash
from .db import get_db, now


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        """SELECT u.*, s.name AS station_name, s.code AS station_code
           FROM users u LEFT JOIN stations s ON s.id=u.station_id
           WHERE u.id=? AND u.active=1""", (user_id,)
    ).fetchone()


def login_user(user):
    token = secrets.token_urlsafe(32)
    session.clear()
    session["user_id"] = user["id"]
    session["session_token"] = token
    session["last_seen"] = now()
    session["csrf_token"] = secrets.token_urlsafe(32)
    db = get_db()
    db.execute("UPDATE users SET session_token=? WHERE id=?", (token, user["id"]))
    db.execute("UPDATE login_sessions SET active=0 WHERE user_id=?", (user["id"],))
    db.execute("INSERT INTO login_sessions(user_id,session_token,ip_address,user_agent,created_at,last_seen,active) VALUES(?,?,?,?,?,?,1)", (user["id"], token, request.remote_addr or "", request.headers.get("User-Agent", "")[:500], now(), now()))
    db.commit()


def logout_user():
    user_id = session.get("user_id")
    if user_id:
        db = get_db()
        token = session.get("session_token")
        db.execute("UPDATE users SET session_token=NULL WHERE id=?", (user_id,))
        if token:
            db.execute("UPDATE login_sessions SET active=0,last_seen=? WHERE session_token=?", (now(), token))
        db.commit()
    session.clear()


def _record_login(username, success):
    db = get_db()
    db.execute("INSERT INTO login_attempts(username,ip_address,success,created_at) VALUES(?,?,?,?)",
               (username.strip(), request.remote_addr or "", 1 if success else 0, now()))
    db.commit()


def _is_locked(username):
    db = get_db()
    cutoff = datetime.now() - timedelta(minutes=current_app.config["LOCK_MINUTES"])
    row = db.execute("""SELECT COUNT(*) c FROM login_attempts
        WHERE username=? AND success=0 AND created_at>=?""",
        (username.strip(), cutoff.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()
    return row["c"] >= current_app.config["LOCK_AFTER_ATTEMPTS"]


def verify_login(username, password):
    username = username.strip()
    if _is_locked(username):
        return None
    user = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        _record_login(username, True)
        return user
    _record_login(username, False)
    return None


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("main.login"))
        last_seen = session.get("last_seen")
        if last_seen:
            try:
                if datetime.now() - datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S") > timedelta(minutes=current_app.config["SESSION_TIMEOUT_MINUTES"]):
                    flash("انتهت الجلسة بسبب عدم النشاط. سجل الدخول مرة أخرى.", "warning")
                    logout_user()
                    return redirect(url_for("main.login"))
            except ValueError:
                pass
        session["last_seen"] = now()
        db = get_db()
        db.execute("UPDATE login_sessions SET last_seen=? WHERE session_token=? AND active=1", (now(), session.get("session_token")))
        db.commit()
        if user["session_token"] and session.get("session_token") != user["session_token"]:
            flash("تم فتح جلسة أخرى لهذا المستخدم. سجل الدخول من جديد.", "warning")
            session.clear()
            return redirect(url_for("main.login"))
        # Maintenance mode is handled centrally before protected views.
        # Super Admin is deliberately exempt from maintenance blocking, but this
        # does NOT bypass authentication, session validation, IP policy, or CSRF.
        if current_app.config.get("ENFORCE_IP_RESTRICTIONS"):
            if user["role"] == "super_admin":
                try:
                    if request.remote_addr and ipaddress.ip_address(request.remote_addr) not in ipaddress.ip_network(current_app.config["SUPER_ADMIN_NETWORK"], strict=False):
                        abort(403)
                except ValueError:
                    abort(403)
            else:
                allowed_ip = (user["allowed_ip"] or "").strip()
                if allowed_ip and request.remote_addr != allowed_ip:
                    abort(403)
        if user["must_change_password"] and request.endpoint != "main.change_password":
            flash("يجب تغيير كلمة المرور قبل متابعة استخدام النظام.", "warning")
            return redirect(url_for("main.change_password"))
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
    if request.method == "POST" and request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400, description="CSRF token invalid")
