import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

# Base Directory of Project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    """Central configuration for CSP_V2 application."""

    BASE_DIR = BASE_DIR
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY or not SECRET_KEY.strip():
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY environment variable is missing or empty. "
            "A secure, stable SECRET_KEY must be configured in the environment (.env) before starting the application."
        )

    # Session Management
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = (os.getenv("SESSION_FILE_DIR") or "").strip() or os.path.join(BASE_DIR, ".flask_session")
    SESSION_FILE_THRESHOLD = int(os.getenv("SESSION_FILE_THRESHOLD", "500"))
    SESSION_CLEANUP_INTERVAL_MINUTES = int(os.getenv("SESSION_CLEANUP_INTERVAL_MINUTES", "15"))
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production" or os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_USE_SIGNER = True

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Account Lockout Protection
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    # Storage Directories
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "audio")
    CASE_RECORDS_FOLDER = os.path.join(BASE_DIR, "case_records")
    GENERATED_FOLDER = os.path.join(BASE_DIR, "generated")
    DATABASE_PATH = (os.getenv("DATABASE_PATH") or "").strip() or os.path.join(BASE_DIR, "complaints.db")
    STATION_CONFIG_PATH = os.path.join(BASE_DIR, "station_config.json")

    # Frontend Assets
    TEMPLATES_FOLDER = os.path.join(BASE_DIR, "frontend", "templates")
    STATIC_FOLDER = os.path.join(BASE_DIR, "frontend", "static")

    # Base URL for Playwright PDF Rendering
    BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")

    # Groq Model Configuration
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GROQ_MODELS = [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "llama-3.3-70b-versatile",
        "meta-llama/llama-4-scout-17b-16e-instruct"
    ]
    GROQ_WHISPER_MODELS = [
        "whisper-large-v3-turbo",
        "whisper-large-v3"
    ]
    SUPPORTED_AUDIO_EXTENSIONS = {
        ".flac", ".mp3", ".mp4", ".mpeg", ".mpga", ".m4a", ".ogg", ".opus", ".wav", ".webm"
    }

    # Storage Configuration (default: local)
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").strip().lower()
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    STORAGE_BUCKET = os.getenv("STORAGE_BUCKET", "complaint-files")

    # HTTP Security Headers Configuration (SEC-05)
    CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "false").lower() == "true"
    HSTS_ENABLED = os.getenv("HSTS_ENABLED", "false").lower() == "true"
    HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))
    # Reserved for future decoupled frontend architecture (e.g., Vercel deployment)
    # Note: Unused in monolithic Flask app; no permissive or wildcard CORS rules are enabled.
    ALLOWED_FRONTEND_ORIGIN = os.getenv("ALLOWED_FRONTEND_ORIGIN", "")

    # Reverse Proxy & Client IP Configuration (SEC-02)
    # Number of trusted upstream proxy hops.
    # On Render (or behind 1 reverse proxy), set to 1 to enable RenderProxyMiddleware.
    # In local development, defaults to 0 so client-supplied forwarded headers are ignored.
    _is_render = os.getenv("RENDER", "").lower() in ("true", "1")
    _is_production = os.getenv("FLASK_ENV") == "production" or os.getenv("ENVIRONMENT") == "production"
    _default_proxies = 1 if (_is_render or _is_production) else 0
    TRUSTED_PROXIES = int(os.getenv("TRUSTED_PROXIES", str(_default_proxies)))
    # X-Forwarded-Proto trust is disabled by default until verified against live Render infrastructure.
    TRUST_FORWARDED_PROTO = os.getenv("TRUST_FORWARDED_PROTO", "false").lower() == "true"

    # Production Debug-Mode & WSGI Security (SEC-06)
    # Debug mode MUST ALWAYS be disabled in production or behind Render to prevent
    # Werkzeug interactive debugger exposure, arbitrary code execution, and secret leakage.
    # In local development, defaults to False and can be enabled via FLASK_DEBUG=1.
    if _is_render or _is_production:
        DEBUG = False
    else:
        DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1")

    # Production Database Pre-Start Validation (Phase 8.10)
    # Strictly requires target database to exist and contain an active administrator before startup.
    # Automatically enabled in production or behind Render; disabled in local development.
    REQUIRE_EXISTING_DB = os.getenv(
        "REQUIRE_EXISTING_DB",
        "true" if (_is_render or _is_production) else "false"
    ).lower() in ("true", "1")

    @classmethod
    def validate_storage_config(cls):
        """
        Validate storage configuration safely without exposing sensitive credentials.
        Fails clearly if Supabase mode is enabled but required variables are missing.
        """
        backend = (cls.STORAGE_BACKEND or "local").strip().lower()
        if backend not in ("local", "supabase"):
            raise ValueError(
                f"Unsupported STORAGE_BACKEND: '{backend}'. Must be 'local' or 'supabase'."
            )
        if backend == "supabase":
            missing = []
            if not cls.SUPABASE_URL:
                missing.append("SUPABASE_URL")
            if not cls.SUPABASE_KEY:
                missing.append("SUPABASE_KEY")
            if not cls.STORAGE_BUCKET:
                missing.append("STORAGE_BUCKET")
            if missing:
                raise ValueError(
                    f"STORAGE_BACKEND is set to 'supabase' but required configuration is missing: {', '.join(missing)}"
                )
