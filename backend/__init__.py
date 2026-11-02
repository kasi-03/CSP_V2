import os
from flask import Flask, g, session, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from config import Config
from backend.services.database import init_db, check_db_health, validate_production_database
from backend.services.auth import get_authenticated_officer, has_permission
from backend.routes import dashboard_bp, complaints_bp, settings_bp, auth_bp, admin_bp

csrf = CSRFProtect()
server_session = Session()


def create_app(config_class=Config):
    """
    Application Factory for Voice-Based AI-Assisted Police Complaint Drafting System.
    Configures template and static folders, ensures necessary storage folders exist,
    initializes SQLite database, configures server-side sessions and CSRF protection,
    and registers modular blueprints.
    """
    app = Flask(
        __name__,
        template_folder=config_class.TEMPLATES_FOLDER,
        static_folder=config_class.STATIC_FOLDER
    )
    app.config.from_object(config_class)

    # Enforce Production Debug-Mode Security (SEC-06)
    # Debug mode MUST ALWAYS be disabled in production or behind Render.
    # Prevents Werkzeug interactive debugger (RCE) and secret/traceback leakage.
    is_production = (
        app.config.get("FLASK_ENV") == "production"
        or os.getenv("FLASK_ENV") == "production"
        or os.getenv("ENVIRONMENT") == "production"
        or os.getenv("RENDER", "").lower() in ("true", "1")
    )
    if is_production:
        app.config["DEBUG"] = False
        app.debug = False

    # Strictly require a valid, non-empty SECRET_KEY for application startup
    secret_key = app.config.get("SECRET_KEY")
    if not secret_key or not str(secret_key).strip():
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY is missing or empty. "
            "A secure, stable SECRET_KEY must be configured in the environment (.env) before starting the application."
        )

    # Ensure vital runtime directories exist
    os.makedirs(config_class.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(config_class.CASE_RECORDS_FOLDER, exist_ok=True)
    os.makedirs(config_class.GENERATED_FOLDER, exist_ok=True)
    os.makedirs(app.config.get("SESSION_FILE_DIR", os.path.join(config_class.BASE_DIR, ".flask_session")), exist_ok=True)
    db_path = app.config.get("DATABASE_PATH", getattr(config_class, "DATABASE_PATH", None))
    if db_path and db_path != ":memory:" and not str(db_path).startswith("file:"):
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    # Initialize extensions
    csrf.init_app(app)
    server_session.init_app(app)

    # Reverse Proxy & Client IP Configuration (SEC-02)
    # Apply RenderProxyMiddleware only when configured with trusted upstream proxies (e.g. Render).
    # Uses fail-safe client IP resolution (CF-Connecting-IP only; no unverified fallbacks).
    # X-Forwarded-Proto is only trusted if explicitly enabled and verified in production.
    trusted_proxies = int(app.config.get("TRUSTED_PROXIES", 0) or 0)
    trust_proto = bool(app.config.get("TRUST_FORWARDED_PROTO", False))
    if trusted_proxies > 0:
        from backend.services.proxy_service import RenderProxyMiddleware
        app.wsgi_app = RenderProxyMiddleware(
            app.wsgi_app,
            trusted_proxies=trusted_proxies,
            trust_forwarded_proto=trust_proto
        )

    # Enforce Pre-Start Production Database Validation (Phase 8.10)
    # Strictly prevents accidental creation of an empty database on persistent storage (e.g. Render).
    if app.config.get("REQUIRE_EXISTING_DB", False):
        validate_production_database(db_path)

    # Initialize SQLite database
    init_db(db_path)

    # Verify session and live account status on every request
    @app.before_request
    def load_current_officer():
        officer_id = session.get("officer_id")
        if officer_id:
            db_path = app.config.get("DATABASE_PATH")
            officer = get_authenticated_officer(officer_id, db_path=db_path)
            if officer:
                g.current_officer = officer
                session["role"] = officer["role"]
            else:
                # Invalidate session if officer account was disabled or deleted
                session.clear()
                g.current_officer = None
        else:
            g.current_officer = None

    # Inject authenticated officer context and permission helper into all templates
    @app.context_processor
    def inject_officer_context():
        return {
            "current_officer": getattr(g, "current_officer", None),
            "has_permission": has_permission
        }

    # Register modular blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(complaints_bp)
    app.register_blueprint(settings_bp)

    # Health Check Endpoint (SEC-07)
    @app.route("/health", methods=["GET"])
    def health_check():
        """
        Lightweight health check endpoint for monitoring on Render.
        Verifies application responsiveness and database connectivity via SELECT 1.
        Returns HTTP 200 {"status": "ok"} when healthy, or HTTP 503 {"status": "unhealthy"} on error.
        Does not require authentication; leaks zero internal diagnostics or paths.
        """
        db_path = app.config.get("DATABASE_PATH")
        if not check_db_health(db_path):
            return jsonify({"status": "unhealthy"}), 503
        return jsonify({"status": "ok"}), 200

    # HTTP Security Headers (SEC-05)
    @app.after_request
    def set_security_headers(response):
        """
        Centrally inject secure HTTP response headers (SEC-05).
        Protects against XSS, clickjacking, MIME sniffing, and device feature abuse.
        """
        # 1. Content-Security-Policy (Strict least-privilege policy)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "media-src 'self' blob:",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'"
        ]
        csp_policy = "; ".join(csp_directives)

        csp_header_name = (
            "Content-Security-Policy-Report-Only"
            if app.config.get("CSP_REPORT_ONLY", False)
            else "Content-Security-Policy"
        )
        response.headers.setdefault(csp_header_name, csp_policy)

        # 2. X-Frame-Options (Clickjacking defense)
        response.headers.setdefault("X-Frame-Options", "DENY")

        # 3. X-Content-Type-Options (MIME-sniffing defense)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")

        # 4. Referrer-Policy
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # 5. Permissions-Policy (Microphone preserved for voice recording; camera/geo/payment/usb disabled)
        response.headers.setdefault(
            "Permissions-Policy",
            "microphone=(self), camera=(), geolocation=(), payment=(), usb=()"
        )

        # 6. Strict-Transport-Security (HSTS) - Enabled only under production HTTPS
        hsts_enabled = app.config.get("HSTS_ENABLED", False)
        if request.is_secure or (hsts_enabled and app.config.get("SESSION_COOKIE_SECURE", False)):
            max_age = app.config.get("HSTS_MAX_AGE", 31536000)
            response.headers.setdefault("Strict-Transport-Security", f"max-age={max_age}")

        return response

    # Provide backwards-compatible endpoint resolution for un-prefixed url_for calls
    def handle_url_build_error(error, endpoint, values):
        for bp in app.blueprints:
            candidate = f"{bp}.{endpoint}"
            if candidate in app.view_functions:
                from flask import url_for as flask_url_for
                return flask_url_for(candidate, **values)
        return None

    app.url_build_error_handlers.append(handle_url_build_error)

    return app
