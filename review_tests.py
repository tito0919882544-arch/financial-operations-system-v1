"""مراجعة آلية لنطاق مركز الصيانة والتشغيل.
تشغل من جذر المشروع:
    python review_tests.py
"""
from pathlib import Path
import ast, re, sys, zipfile, sqlite3

ROOT = Path(__file__).resolve().parent
errors=[]; warnings=[]

def ok(msg): print("PASS  ", msg)
def warn(msg): warnings.append(msg); print("WARN  ", msg)
def fail(msg): errors.append(msg); print("FAIL  ", msg)

# 1) Required project structure
required_files = [
    "run.py","config.py","requirements.txt","app/__init__.py","app/db.py",
    "app/routes.py","app/security.py","app/services.py","templates/base.html",
    "templates/login.html","templates/maintenance_center.html",
    "templates/maintenance.html","templates/maintenance_themes.html",
    "templates/notifications.html","templates/global_search.html",
    "templates/help_topic.html","templates/operation_detail.html",
    "templates/operation_form.html"
]
for f in required_files:
    (ok if (ROOT/f).is_file() else fail)(f"وجود {f}")

# 2) Python compilation / AST
py_files=list(ROOT.rglob("*.py"))
for f in py_files:
    try:
        ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
    except Exception as e:
        fail(f"Python syntax: {f.relative_to(ROOT)}: {e}")
if not errors: ok(f"تحليل Python AST لجميع الملفات ({len(py_files)})")

routes=(ROOT/"app/routes.py").read_text(encoding="utf-8")
dbpy=(ROOT/"app/db.py").read_text(encoding="utf-8")
base=(ROOT/"templates/base.html").read_text(encoding="utf-8")

# 3) Required routes
required_route_fragments=[
    '"/maintenance"', '"/maintenance-status"', '"/maintenance/status"',
    '"/maintenance/diagnostics"', '"/maintenance/backup"',
    '"/maintenance/password-reset/', '"/maintenance/session/',
    '"/notifications"', '"/search"', '"/help/<topic>"',
    '"/operation/<int:operation_id>/preflight"',
    '"/operation/<int:operation_id>/bundle"',
    '"/operation/<int:operation_id>/resume"',
    '"/maintenance/operations-monitor"'
]
for frag in required_route_fragments:
    (ok if frag in routes else fail)(f"المسار {frag}")

# 4) Audit immutability and logging hooks
for frag in ["CREATE TRIGGER IF NOT EXISTS audit_events_no_update",
             "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete"]:
    (ok if frag in dbpy else fail)(f"حماية سجل التدقيق: {frag}")
for frag in ["log_event(", "log_action(", "push_notification("]:
    (ok if frag in routes else warn)(f"وجود نقطة تكامل {frag}")

# 5) Maintenance super-admin bypass must exist before protected pages
if 'if user["role"] == "super_admin":\n        return' in routes:
    ok("Super Admin مستثنى من حجب وضع الصيانة على مستوى guard")
else:
    fail("لم يُثبت استثناء Super Admin في maintenance guard")

# 6) Theme application is server-side, not only UI
for frag in ['set_setting("theme"', 'set_setting("custom_css"', 'SYSTEM_SETTINGS.get("custom_css")']:
    (ok if frag in (routes+base) else fail)(f"تطبيق Theme فعلي: {frag}")

# 7) Notifications: storage + read routes + role targeting
for frag in ["CREATE TABLE IF NOT EXISTS notifications","/notifications/<int:notification_id>/read","role_target"]:
    (ok if frag in (dbpy+routes) else fail)(f"الإشعارات: {frag}")

# 8) Petty cash station/month isolation
for frag in ['petty_cash_items','station_id=? AND month_key=?','allocated_amount']:
    (ok if frag in routes else fail)(f"عزل النثرية: {frag}")

# 9) Operation lifecycle helpers
for frag in ["operation_step(", "operation_preflight(", "operation_bundle(", "operation_resume("]:
    (ok if frag in routes else fail)(f"دورة العملية: {frag}")

# 10) Scan templates for obvious invalid Jinja operators/undefined dot access pattern
# The previous known error was item.remaining<=...*.15. Jinja permits arithmetic, but
# method/attribute syntax must be valid; detect Python-only constructs that often break.
for f in (ROOT/"templates").glob("*.html"):
    txt=f.read_text(encoding="utf-8")
    if "{{" in txt and "}}" not in txt:
        fail(f"قالب غير متوازن: {f.name}")
    if "{%" in txt and "%}" not in txt:
        fail(f"قالب Jinja غير متوازن: {f.name}")

# 11) Security: state-changing maintenance routes should require super_admin
maintenance_mutations = re.findall(r'@bp\.(?:post|route)\(([^)]*)\)\n@require_role\(([^)]*)\)\ndef ([a-zA-Z0-9_]+)', routes)
for args, roles, fn in maintenance_mutations:
    if "maintenance" in fn and "super_admin" not in roles:
        warn(f"تحقق يدوي من صلاحية {fn}")

print("\nRESULT")
print(f"FAIL={len(errors)} WARN={len(warnings)}")
if errors:
    print("REVIEW_FAILED")
    sys.exit(1)
print("REVIEW_STATIC_PASS")
if warnings:
    print("تنبيه: توجد نقاط تحقق يدوي في التقرير.")
