"""
Administrator routes blueprint for CSP_V2.

Provides:
- GET /admin/officers: List all officer accounts.
- GET & POST /admin/officers/create: Provision new officer accounts.
- POST /admin/officers/<int:officer_id>/toggle-status: Activate / deactivate officer.
- POST /admin/officers/<int:officer_id>/change-role: Change role of officer.
- POST /admin/officers/<int:officer_id>/reset-password: Reset officer password.
- GET /admin/audit-logs: Paginated audit log viewer with filtering.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    current_app,
    g
)
from backend.services.auth import (
    require_role,
    hash_password,
    validate_password_strength,
    can_manage_admin
)
from backend.services.database import (
    list_officers,
    get_officer_by_id,
    get_officer_by_username,
    create_officer,
    update_officer_status,
    update_officer_role,
    update_officer_status_atomic,
    update_officer_role_atomic,
    update_officer_password,
    get_audit_logs_paginated,
    create_audit_log,
    ALLOWED_ROLES
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/officers", methods=["GET"], endpoint="list_officers")
@require_role("admin")
def officers_list():
    """List all registered officers with their status, role, badge, and activity."""
    db_path = current_app.config.get("DATABASE_PATH")
    officers = list_officers(include_inactive=True, db_path=db_path)
    return render_template(
        "admin/officers.html",
        officers=officers,
        allowed_roles=sorted(list(ALLOWED_ROLES))
    )


@admin_bp.route("/officers/create", methods=["GET", "POST"], endpoint="create_officer")
@require_role("admin")
def officer_create():
    """Create a new officer account with role assignment and password complexity."""
    db_path = current_app.config.get("DATABASE_PATH")
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        badge_number = request.form.get("badge_number", "").strip() or None
        role = request.form.get("role", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or len(username) < 3:
            error = "Username must be at least 3 characters long."
        elif not full_name:
            error = "Full name cannot be empty."
        elif role not in ALLOWED_ROLES:
            error = f"Invalid role selected. Allowed roles: {', '.join(sorted(ALLOWED_ROLES))}"
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            is_valid, msg = validate_password_strength(password)
            if not is_valid:
                error = msg
            else:
                existing = get_officer_by_username(username, db_path=db_path)
                if existing:
                    error = f"An officer with username '{username}' already exists."
                else:
                    pwd_hash = hash_password(password)
                    new_officer_id = create_officer(
                        username=username,
                        password_hash=pwd_hash,
                        full_name=full_name,
                        role=role,
                        badge_number=badge_number,
                        db_path=db_path
                    )
                    # Audit log creation
                    admin_officer = getattr(g, "current_officer", {})
                    create_audit_log(
                        officer_id=admin_officer.get("id"),
                        username=admin_officer.get("username"),
                        ip_address=request.remote_addr or "unknown",
                        action="OFFICER_CREATED",
                        resource=f"officers/{new_officer_id}",
                        status="SUCCESS",
                        details=f"Admin created officer '{username}' with role '{role}'",
                        db_path=db_path
                    )
                    return redirect(url_for("admin.list_officers"))

    status_code = 400 if error else 200
    return render_template(
        "admin/officer_create.html",
        error=error,
        allowed_roles=sorted(list(ALLOWED_ROLES))
    ), status_code


@admin_bp.route("/officers/<int:officer_id>/toggle-status", methods=["POST"], endpoint="toggle_officer_status")
@require_role("admin")
def toggle_status(officer_id: int):
    """
    Activate or deactivate an officer account.
    Enforces that the last active Administrator cannot be deactivated.
    """
    db_path = current_app.config.get("DATABASE_PATH")
    officer = get_officer_by_id(officer_id, include_hash=False, db_path=db_path)
    if not officer:
        return render_template("error.html", message="Officer account not found."), 404

    target_status = not officer["is_active"]
    action_type = "activate" if target_status else "deactivate"

    # Safety check: atomically enforce that the last active Admin cannot be deactivated
    success, reason = update_officer_status_atomic(officer_id, is_active=target_status, db_path=db_path)
    if not success:
        return render_template("error.html", message=reason), 400

    admin_officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=admin_officer.get("id"),
        username=admin_officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action=f"OFFICER_{action_type.upper()}D",
        resource=f"officers/{officer_id}",
        status="SUCCESS",
        details=f"Admin {action_type}d officer '{officer.get('username')}'",
        db_path=db_path
    )
    return redirect(url_for("admin.list_officers"))


@admin_bp.route("/officers/<int:officer_id>/change-role", methods=["POST"], endpoint="change_officer_role")
@require_role("admin")
def change_role(officer_id: int):
    """
    Change the role of an officer.
    Enforces that the last active Administrator cannot be demoted.
    """
    db_path = current_app.config.get("DATABASE_PATH")
    new_role = request.form.get("role", "").strip().lower()
    if new_role not in ALLOWED_ROLES:
        return render_template("error.html", message="Invalid role specified."), 400

    officer = get_officer_by_id(officer_id, include_hash=False, db_path=db_path)
    if not officer:
        return render_template("error.html", message="Officer account not found."), 404

    old_role = officer.get("role")

    # Safety check: atomically enforce that the last active Admin cannot be demoted
    success, reason = update_officer_role_atomic(officer_id, new_role=new_role, db_path=db_path)
    if not success:
        return render_template("error.html", message=reason), 400

    admin_officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=admin_officer.get("id"),
        username=admin_officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action="OFFICER_ROLE_CHANGED",
        resource=f"officers/{officer_id}",
        status="SUCCESS",
        details=f"Role changed from '{old_role}' to '{new_role}' for officer '{officer.get('username')}'",
        db_path=db_path
    )
    return redirect(url_for("admin.list_officers"))


@admin_bp.route("/officers/<int:officer_id>/reset-password", methods=["POST"], endpoint="reset_officer_password")
@require_role("admin")
def reset_password(officer_id: int):
    """Reset an officer's password, enforcing password policy."""
    db_path = current_app.config.get("DATABASE_PATH")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    officer = get_officer_by_id(officer_id, include_hash=False, db_path=db_path)
    if not officer:
        return render_template("error.html", message="Officer account not found."), 404

    if new_password != confirm_password:
        return render_template("error.html", message="Passwords do not match."), 400

    is_valid, msg = validate_password_strength(new_password)
    if not is_valid:
        return render_template("error.html", message=f"Password error: {msg}"), 400

    pwd_hash = hash_password(new_password)
    update_officer_password(officer_id, pwd_hash, db_path=db_path)

    admin_officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=admin_officer.get("id"),
        username=admin_officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action="OFFICER_PASSWORD_RESET",
        resource=f"officers/{officer_id}",
        status="SUCCESS",
        details=f"Password reset by Admin for officer '{officer.get('username')}'",
        db_path=db_path
    )
    return redirect(url_for("admin.list_officers"))


@admin_bp.route("/audit-logs", methods=["GET"], endpoint="audit_logs")
@require_role("admin")
def audit_logs():
    """Paginated view of application security and operational audit logs."""
    db_path = current_app.config.get("DATABASE_PATH")
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    action_filter = request.args.get("action", "").strip() or None
    username_filter = request.args.get("username", "").strip() or None

    pagination = get_audit_logs_paginated(
        page=page,
        per_page=20,
        action_filter=action_filter,
        username_filter=username_filter,
        db_path=db_path
    )

    return render_template(
        "admin/audit_logs.html",
        logs=pagination["logs"],
        total=pagination["total"],
        page=pagination["page"],
        per_page=pagination["per_page"],
        total_pages=pagination["total_pages"],
        action_filter=action_filter or "",
        username_filter=username_filter or ""
    )
