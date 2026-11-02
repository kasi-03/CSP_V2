from flask import Blueprint, render_template
from backend.services.database import get_complaints, get_statistics
from backend.services.auth import require_login

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/", endpoint="dashboard")
@require_login
def dashboard():
    """Render the main dashboard with statistics and complaint history."""
    complaints = get_complaints()
    total_cases, today_cases, month_cases = get_statistics()

    return render_template(
        "dashboard.html",
        complaints=complaints,
        total_cases=total_cases,
        today_cases=today_cases,
        month_cases=month_cases
    )
