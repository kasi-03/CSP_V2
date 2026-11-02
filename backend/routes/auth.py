"""
Authentication routes blueprint for CSP_V2.

Provides:
- GET /login: Displays secure police login page.
- POST /login: Authenticates officer, rotates session, protects against brute-force & open redirects.
- POST /logout: Securely terminates officer session (POST-only).
"""

from urllib.parse import urlparse, urljoin
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    current_app
)
from backend.services.auth import (
    authenticate_officer,
    get_authenticated_officer
)
from backend.services.database import create_audit_log

auth_bp = Blueprint("auth", __name__)


def is_safe_url(target: str) -> bool:
    """
    Validate redirect target to prevent open redirect vulnerabilities.
    Ensures target belongs to the current application host.
    """
    if not target or not isinstance(target, str):
        return False
    # Reject javascript: or data: URIs and scheme-relative URLs like '//evil.com'
    if target.startswith("//") or target.startswith("\\\\"):
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


@auth_bp.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    """
    Officer login endpoint.
    GET: Renders login page with CSRF protection.
    POST: Verifies credentials, rotates session, enforces lockout, and prevents open redirects.
    """
    db_path = current_app.config.get("DATABASE_PATH")

    # If officer is already authenticated, redirect directly to dashboard
    current_officer_id = session.get("officer_id")
    if current_officer_id:
        active_officer = get_authenticated_officer(current_officer_id, db_path=db_path)
        if active_officer:
            return redirect(url_for("dashboard"))
        else:
            # Stale session for deactivated or deleted account
            session.clear()

    next_url = request.args.get("next") or request.form.get("next", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr or "unknown"

        officer, error_msg = authenticate_officer(
            username=username,
            password=password,
            ip_address=ip_address,
            db_path=db_path
        )

        if error_msg or not officer:
            return render_template(
                "login.html",
                error=error_msg,
                username=username,
                next_url=next_url
            ), 401

        # Clear any prior session state to prevent session fixation attacks
        session.clear()

        # Establish fresh authenticated session
        session["officer_id"] = officer["id"]
        session["username"] = officer["username"]
        session["full_name"] = officer["full_name"]
        session["role"] = officer["role"]
        session["badge_number"] = officer.get("badge_number")
        session.permanent = True

        # Safe redirect
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html", error=None, next_url=next_url)


@auth_bp.route("/logout", methods=["POST"], endpoint="logout")
def logout():
    """
    Officer logout endpoint.
    Restricted to POST method only to mitigate Cross-Site Request Forgery logouts.
    """
    officer_id = session.get("officer_id")
    username = session.get("username")
    ip_address = request.remote_addr or "unknown"
    db_path = current_app.config.get("DATABASE_PATH")

    if officer_id:
        create_audit_log(
            officer_id=officer_id,
            username=username,
            ip_address=ip_address,
            action="LOGOUT",
            resource="auth/logout",
            status="SUCCESS",
            details="User logged out",
            db_path=db_path
        )

    # Invalidate session on server and client
    session.clear()
    return redirect(url_for("auth.login"))
