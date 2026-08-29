import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
BACKUP_DIR = BASE_DIR / "backups"

DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

DATABASE_PATH = os.environ.get("DALGO_DATABASE_PATH", str(DATA_DIR / "financial_control.sqlite3"))
SECRET_KEY = os.environ.get("DALGO_SECRET_KEY", "change-this-secret-key-before-production")

# عند التجربة الأولى اتركها False حتى لا يمنعك اختلاف IP من الدخول.
# عند التشغيل الرسمي داخل الشبكة يمكن جعلها True وربط كل مستخدم بعنوان IP محدد من شاشة المستخدمين/قاعدة البيانات.
ENFORCE_IP_RESTRICTIONS = os.environ.get("DALGO_ENFORCE_IP", "false").lower() == "true"

SESSION_TIMEOUT_MINUTES = int(os.environ.get("DALGO_SESSION_TIMEOUT_MINUTES", "20"))
MAX_CONTENT_LENGTH = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}

DEFAULT_STATION_CODE = "DLG"
DEFAULT_STATION_NAME = "محطة الفحص الآلي دلقو"
DEFAULT_COMPANY_NAME = "شركة الوكيل لخدمات المرور"
DEFAULT_MANAGER_NAME = "مدير محطة دلقو"
