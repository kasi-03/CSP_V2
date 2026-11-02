from flask import Blueprint, render_template, request, redirect, url_for, g, current_app
from backend.services.ai_generator import english_to_telugu
from backend.services.auth import require_role
from backend.services.database import create_audit_log
from backend.utils.station import load_station, save_station

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings", endpoint="settings")
@require_role("admin")
def settings():
    """Render the police station location settings form."""
    station = load_station()
    return render_template(
        "settings.html",
        station=station
    )


@settings_bp.route("/save_settings", methods=["POST"], endpoint="save_settings")
@require_role("admin")
def save_settings_route():
    """Save updated station details with AI-assisted Telugu translation."""
    station_name = request.form["station_name"]
    place = request.form["place"]
    district = request.form["district"]

    station_name_telugu = english_to_telugu(station_name)
    place_telugu = english_to_telugu(place)
    district_telugu = english_to_telugu(district)

    data = {
        "station_name": station_name,
        "place": place,
        "district": district,
        "station_name_telugu": station_name_telugu,
        "place_telugu": place_telugu,
        "district_telugu": district_telugu
    }

    save_station(data)

    # Record audit log
    officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=officer.get("id"),
        username=officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action="STATION_SETTINGS_UPDATED",
        resource="settings/station",
        status="SUCCESS",
        details=f"Station settings updated: {station_name}, {place}, {district}",
        db_path=current_app.config.get("DATABASE_PATH")
    )

    return redirect(url_for("dashboard"))
