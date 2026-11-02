import os
from pathlib import Path
from datetime import datetime
from config import Config


def build_case_name(complaint_id: int, complainant_name: str, date_str: str) -> str:
    """Construct standardized case name identifier (e.g., C001_Name_19-10-2026)."""
    sanitized_name = complainant_name.replace(" ", "_")
    return f"C{complaint_id:03d}_{sanitized_name}_{date_str}"


def build_case_name_from_registered(complaint_id: int, complainant_name: str, registered_on: str) -> str:
    """Format case name from the registered_on timestamp string."""
    try:
        date_str = datetime.strptime(registered_on, "%d-%m-%Y %I:%M %p").strftime("%d-%m-%Y")
    except Exception:
        date_str = datetime.now().strftime("%d-%m-%Y")
    return build_case_name(complaint_id, complainant_name, date_str)


def get_case_folder(complaint_id: int, complainant_name: str) -> tuple[Path, str]:
    """Create and return the filesystem directory for a new case."""
    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%B")
    date_str = now.strftime("%d-%m-%Y")

    case_folder_name = build_case_name(complaint_id, complainant_name, date_str)
    case_folder = Path(Config.CASE_RECORDS_FOLDER, year, month, case_folder_name)
    case_folder.mkdir(parents=True, exist_ok=True)

    return case_folder, case_folder_name
