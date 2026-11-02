"""
Authentication and Officer Credential Service for CSP_V2.

Provides:
1. Secure password hashing using Werkzeug scrypt.
2. Password verification via constant-time comparison.
3. Password strength policy enforcement.
4. Officer authentication with brute-force / lockout checks.
5. Inactive account validation.
6. Audit logging of login events.
7. Safe officer data retrieval with zero password hash leakage.
"""

import re
from functools import wraps
from typing import Optional, Tuple, Dict, Any, Set
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, redirect, url_for, session, current_app, g, abort, render_template

from config import Config
from backend.services.database import (
    get_officer_by_username,
    get_officer_by_id,
    record_login,
    create_audit_log,
    record_login_attempt,
    is_login_locked,
    clear_failed_login_attempts,
    count_active_admins
)

GENERIC_AUTH_ERROR = "Invalid username or password."


def hash_password(password: str) -> str:
    """
    Hash a plain-text password using Werkzeug's scrypt algorithm.
    """
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")
    return generate_password_hash(password, method="scrypt")


def verify_password(password_hash: str, password: str) -> bool:
    """
    Verify a plain-text password against a stored password hash using constant-time comparison.
    """
    if not password_hash or not password:
        return False
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforce strong police administration password policy:
    - Minimum 8 characters.
    - At least one uppercase letter.
    - At least one lowercase letter.
    - At least one digit.
    - At least one special symbol.
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\\/~`]", password):
        return False, "Password must contain at least one special symbol."
    return True, ""


def authenticate_officer(
    username: str,
    password: str,
    ip_address: Optional[str] = None,
    db_path: Optional[str] = None
) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Authenticate an officer by username and password.

    Enforces:
    - Persistent SQLite lockout after max failed attempts.
    - Active account check.
    - Audit logging of success and failure.
    - Generic error messages to prevent account enumeration.
    - Safe return value stripped of all password hashes.

    Returns: (safe_officer_dict, error_message)
    """
    clean_user = (username or "").strip()
    clean_pass = password or ""
    clean_ip = (ip_address or "unknown").strip()

    if not clean_user or not clean_pass:
        return None, GENERIC_AUTH_ERROR

    # 1. Lockout check
    max_attempts = getattr(Config, "MAX_FAILED_LOGIN_ATTEMPTS", 5)
    lockout_minutes = getattr(Config, "LOCKOUT_DURATION_MINUTES", 15)
    locked, remaining_mins = is_login_locked(
        clean_user,
        ip_address=clean_ip,
        max_attempts=max_attempts,
        window_minutes=lockout_minutes,
        db_path=db_path
    )
    if locked:
        create_audit_log(
            officer_id=None,
            username=clean_user,
            ip_address=clean_ip,
            action="LOGIN_LOCKED",
            resource="auth/login",
            status="BLOCKED",
            details=f"Account locked. Remaining lockout: {remaining_mins} minutes.",
            db_path=db_path
        )
        return None, f"Too many failed login attempts. Please try again in {remaining_mins} minute(s)."

    # 2. Look up officer
    officer = get_officer_by_username(clean_user, db_path=db_path)
    if not officer:
        record_login_attempt(clean_user, ip_address=clean_ip, success=False, db_path=db_path)
        create_audit_log(
            officer_id=None,
            username=clean_user,
            ip_address=clean_ip,
            action="LOGIN_FAILED",
            resource="auth/login",
            status="FAILED",
            details="User not found",
            db_path=db_path
        )
        return None, GENERIC_AUTH_ERROR

    # 3. Active account check
    if not officer.get("is_active", False):
        record_login_attempt(clean_user, ip_address=clean_ip, success=False, db_path=db_path)
        create_audit_log(
            officer_id=officer.get("id"),
            username=clean_user,
            ip_address=clean_ip,
            action="LOGIN_FAILED",
            resource="auth/login",
            status="FAILED",
            details="Account is inactive/suspended",
            db_path=db_path
        )
        return None, GENERIC_AUTH_ERROR

    # 4. Verify password hash
    stored_hash = officer.get("password_hash", "")
    if not verify_password(stored_hash, clean_pass):
        record_login_attempt(clean_user, ip_address=clean_ip, success=False, db_path=db_path)
        create_audit_log(
            officer_id=officer.get("id"),
            username=clean_user,
            ip_address=clean_ip,
            action="LOGIN_FAILED",
            resource="auth/login",
            status="FAILED",
            details="Incorrect password",
            db_path=db_path
        )
        return None, GENERIC_AUTH_ERROR

    # 5. Success: update records and reset failed attempts
    record_login_attempt(clean_user, ip_address=clean_ip, success=True, db_path=db_path)
    clear_failed_login_attempts(clean_user, db_path=db_path)
    record_login(officer["id"], db_path=db_path)

    create_audit_log(
        officer_id=officer["id"],
        username=clean_user,
        ip_address=clean_ip,
        action="LOGIN_SUCCESS",
        resource="auth/login",
        status="SUCCESS",
        details="Authenticated successfully",
        db_path=db_path
    )

    # Return safe officer dictionary (NEVER expose password hash)
    safe_officer = {
        "id": officer["id"],
        "username": officer["username"],
        "full_name": officer["full_name"],
        "badge_number": officer["badge_number"],
        "role": officer["role"],
        "is_active": officer["is_active"],
        "created_at": officer["created_at"],
        "last_login": officer["last_login"]
    }
    return safe_officer, ""


def get_authenticated_officer(officer_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve current officer by primary key ID and confirm active status.
    Returns None if officer does not exist or has been disabled.
    """
    if not officer_id or not isinstance(officer_id, int):
        return None

    officer = get_officer_by_id(officer_id, include_hash=False, db_path=db_path)
    if not officer or not officer.get("is_active", False):
        return None

    return officer


# =====================================================================
# Role-Based Access Control (RBAC) & Authorization Services
# =====================================================================

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "view_complaints",
        "create_complaint",
        "manage_settings",
        "manage_officers",
        "view_audit_logs",
        "download_files"
    },
    "officer": {
        "view_complaints",
        "create_complaint",
        "download_files"
    },
    "viewer": {
        "view_complaints",
        "download_files"
    }
}


def has_permission(officer: Optional[dict], permission: str) -> bool:
    """
    Check if an officer possesses a given permission.
    Never trusts browser input; relies solely on active officer record.
    """
    if not officer or not officer.get("is_active"):
        return False
    role = (officer.get("role") or "").lower()
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_login(view_func):
    """
    Centralized route decorator to ensure the request is from an authenticated officer.
    Validates current active officer status in the database on every invocation.
    If unauthenticated:
      - File downloads or API endpoints: abort(401)
      - Web pages: Redirects to /login?next=<requested_url>
    """
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        officer_id = session.get("officer_id")
        if not officer_id:
            if (request.path.startswith("/complaints/") and "/files/" in request.path) or request.path.startswith("/case_audio/"):
                abort(401)
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for("auth.login", next=next_url))

        db_path = current_app.config.get("DATABASE_PATH") if current_app else None
        officer = get_authenticated_officer(officer_id, db_path=db_path)
        if not officer:
            # Active account terminated or deactivated mid-session
            session.clear()
            if (request.path.startswith("/complaints/") and "/files/" in request.path) or request.path.startswith("/case_audio/"):
                abort(401)
            return redirect(url_for("auth.login"))

        g.current_officer = officer
        return view_func(*args, **kwargs)
    return decorated_view


def require_role(*allowed_roles: str):
    """
    Centralized route decorator enforcing strict Role-Based Access Control (RBAC).
    Allowed roles: 'admin', 'officer', 'viewer'.
    Never trusts browser session role; resolves the live role directly from the database.
    If role does not match:
      - Records an UNAUTHORIZED_ACCESS audit log.
      - Returns 403 Forbidden with error template.
    """
    normalized_roles = {r.lower().strip() for r in allowed_roles}

    def decorator(view_func):
        @wraps(view_func)
        def decorated_view(*args, **kwargs):
            officer_id = session.get("officer_id")
            if not officer_id:
                if (request.path.startswith("/complaints/") and "/files/" in request.path) or request.path.startswith("/case_audio/"):
                    abort(401)
                next_url = request.full_path if request.query_string else request.path
                return redirect(url_for("auth.login", next=next_url))

            db_path = current_app.config.get("DATABASE_PATH") if current_app else None
            officer = get_authenticated_officer(officer_id, db_path=db_path)
            if not officer:
                session.clear()
                if (request.path.startswith("/complaints/") and "/files/" in request.path) or request.path.startswith("/case_audio/"):
                    abort(401)
                return redirect(url_for("auth.login"))

            g.current_officer = officer
            current_role = (officer.get("role") or "").lower()

            if current_role not in normalized_roles:
                # Audit log unauthorized privilege escalation attempt
                create_audit_log(
                    officer_id=officer.get("id"),
                    username=officer.get("username"),
                    ip_address=request.remote_addr or "unknown",
                    action="UNAUTHORIZED_ACCESS",
                    resource=request.path,
                    status="DENIED",
                    details=f"Officer '{officer.get('username')}' (role: {current_role}) denied access to endpoint requiring {sorted(list(normalized_roles))}",
                    db_path=db_path
                )
                if (request.path.startswith("/complaints/") and "/files/" in request.path) or request.path.startswith("/case_audio/"):
                    abort(403)
                return render_template(
                    "error.html",
                    message="Access Denied: You do not have the required role to access this page."
                ), 403

            return view_func(*args, **kwargs)
        return decorated_view
    return decorator


def can_manage_admin(admin_id_to_modify: int, action: str, db_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Safety constraint: Enforces that the last active Administrator account cannot be
    accidentally demoted, deactivated, or deleted.
    Returns: (is_permitted: bool, error_message: str)
    """
    officer = get_officer_by_id(admin_id_to_modify, include_hash=False, db_path=db_path)
    if not officer:
        return False, "Officer account not found."

    if (officer.get("role") or "").lower() == "admin" and officer.get("is_active"):
        active_admin_count = count_active_admins(db_path=db_path)
        if active_admin_count <= 1 and action in ("deactivate", "demote", "delete"):
            return False, "Cannot modify account: At least one active Administrator must remain in the system."

    return True, ""


