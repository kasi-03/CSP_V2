"""
PDF Generation Service for CSP_V2.

Renders Telugu and English formal complaint documents directly to PDF using
Flask's in-memory template rendering engine and Playwright (with system Chrome).

Security & Architectural Principles:
1. Eliminates unauthenticated loopback HTTP calls: renders templates directly in Python memory.
2. Inlines stylesheet and font assets to avoid network fetches during PDF conversion.
3. Completely immune to HTTP redirect-to-login vulnerabilities (SEC-01).
4. Strictly preserves existing legal layout, typography, Telugu fonts, margins, and print styling.
5. Does not leak sensitive complaint details in exception logs.
"""

import os
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

from config import Config
from backend.services.database import get_complaint_by_id
from backend.utils.station import load_station
from backend.utils.file_helpers import build_case_name_from_registered
from backend.services.ai_generator import translate_subject


def _get_css_with_fonts() -> str:
    """Load complaint.css and resolve font URLs to absolute file URIs for headless rendering."""
    static_dir = Path(Config.STATIC_FOLDER).resolve()
    css_file = static_dir / "css" / "complaint.css"
    if not css_file.exists():
        return ""

    try:
        with open(css_file, "r", encoding="utf-8") as f:
            css_content = f.read()

        font_file = (static_dir / "fonts" / "TiroTelugu-Regular.ttf").resolve()
        if font_file.exists():
            font_uri = font_file.as_uri()
            css_content = css_content.replace("../fonts/TiroTelugu-Regular.ttf", font_uri)

        return css_content
    except Exception:
        return ""


def _inline_css_in_html(html: str) -> str:
    """Inject the complaint stylesheet directly into <style> tags to avoid external asset fetches."""
    css_content = _get_css_with_fonts()
    if not css_content:
        return html

    style_tag = f"<style>\n{css_content}\n</style>"

    # Replace existing stylesheet link with inline style tag
    replaced = re.sub(
        r'<link\s+[^>]*href=["\'][^"\']*complaint\.css["\'][^>]*>',
        style_tag,
        html,
        flags=re.IGNORECASE
    )
    if replaced != html:
        return replaced

    # Fallback: inject into </head>
    if "</head>" in html:
        return html.replace("</head>", f"{style_tag}\n</head>", 1)

    return f"{style_tag}\n{html}"


def save_html_as_pdf(html: str, output_path: str):
    """Render an HTML string as an A4 PDF using Playwright with system Chrome."""
    from playwright.sync_api import sync_playwright

    processed_html = _inline_css_in_html(html)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="chrome", headless=True)
        except Exception:
            browser = p.chromium.launch(headless=True)

        page = browser.new_page()
        page.set_content(processed_html, wait_until="load")

        page.pdf(
            path=output_path,
            format="A4",
            print_background=True,
            margin={
                "top": "10mm",
                "bottom": "10mm",
                "left": "10mm",
                "right": "10mm"
            }
        )
        browser.close()


def _render_template_safe(template_name: str, **context) -> str:
    """Render template safely whether inside an active HTTP request or in background/test context."""
    from flask import render_template, has_request_context, has_app_context, current_app

    if has_request_context():
        return render_template(template_name, **context)

    if has_app_context() and current_app:
        app = current_app._get_current_object()
    else:
        from backend import create_app
        app = create_app()

    with app.test_request_context("/"):
        return render_template(template_name, **context)


def render_telugu_complaint_html(complaint_id: int, db_path: Optional[str] = None) -> str:
    """Render the formal Telugu complaint HTML for a given complaint ID."""
    from flask import has_app_context, current_app

    resolved_db = db_path
    if not resolved_db and has_app_context() and current_app:
        resolved_db = current_app.config.get("DATABASE_PATH")

    complaint = get_complaint_by_id(complaint_id, db_path=resolved_db)
    if not complaint:
        raise ValueError(f"Complaint record #{complaint_id} not found.")

    station = load_station()
    case_name = build_case_name_from_registered(complaint[0], complaint[2], complaint[1])

    return _render_template_safe(
        "result.html",
        complaint=complaint[7],
        subject=complaint[5],
        complainant_name=complaint[3],
        phone_number=complaint[4],
        station_name=station.get("station_name", ""),
        place=station.get("place", ""),
        district=station.get("district", ""),
        station_name_telugu=station.get("station_name_telugu", ""),
        place_telugu=station.get("place_telugu", ""),
        district_telugu=station.get("district_telugu", ""),
        current_date=datetime.now().strftime("%d-%m-%Y"),
        complaint_id=complaint_id,
        case_name=case_name
    )


def render_english_complaint_html(complaint_id: int, db_path: Optional[str] = None) -> str:
    """Render the formal English complaint HTML for a given complaint ID."""
    from flask import has_app_context, current_app

    resolved_db = db_path
    if not resolved_db and has_app_context() and current_app:
        resolved_db = current_app.config.get("DATABASE_PATH")

    complaint = get_complaint_by_id(complaint_id, db_path=resolved_db)
    if not complaint:
        raise ValueError(f"Complaint record #{complaint_id} not found.")

    station = load_station()
    case_name = build_case_name_from_registered(complaint[0], complaint[2], complaint[1])

    return _render_template_safe(
        "english.html",
        english=complaint[8],
        subject=translate_subject(complaint[5]),
        complainant_name=complaint[2],
        phone_number=complaint[4],
        current_date=datetime.now().strftime("%d-%m-%Y"),
        station_name=station.get("station_name", ""),
        place=station.get("place", ""),
        district=station.get("district", ""),
        case_name=case_name
    )


def generate_telugu_pdf(filename: str, complaint_id: int, db_path: Optional[str] = None):
    """Generate Telugu complaint PDF from in-memory rendered template without loopback HTTP calls."""
    html = render_telugu_complaint_html(complaint_id, db_path=db_path)
    save_html_as_pdf(html, filename)


def generate_english_pdf(filename: str, complaint_id: int, db_path: Optional[str] = None):
    """Generate English complaint PDF from in-memory rendered template without loopback HTTP calls."""
    html = render_english_complaint_html(complaint_id, db_path=db_path)
    save_html_as_pdf(html, filename)


def save_page_as_pdf(url: str, output_path: str):
    """Deprecated legacy wrapper for backward compatibility with older test suites."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="chrome", headless=True)
        except Exception:
            browser = p.chromium.launch(headless=True)

        page = browser.new_page()
        page.goto(url, wait_until="networkidle")

        page.pdf(
            path=output_path,
            format="A4",
            print_background=True,
            margin={
                "top": "10mm",
                "bottom": "10mm",
                "left": "10mm",
                "right": "10mm"
            }
        )
        browser.close()
