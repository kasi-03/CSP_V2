import os
import re
import shutil
from typing import Union
from pathlib import Path
from datetime import datetime
from flask import Blueprint, render_template, request, send_file, redirect, abort, g, current_app, session
from config import Config
from backend.services.auth import require_login, require_role
from backend.services.ai_generator import (
    generate_complaint,
    translate_to_english,
    generate_subject,
    english_to_telugu,
    translate_subject,
    clean_speech
)
from backend.services.speech import speech_to_text
from backend.services.pdf_generator import (
    generate_telugu_pdf,
    generate_english_pdf
)
from backend.services.database import (
    save_complaint,
    get_complaint_by_id,
    get_connection,
    update_audio_path,
    update_complaint_storage,
    get_complaint_storage_info,
    create_audit_log
)
from backend.services.storage import (
    get_storage_service,
    build_storage_key,
    get_content_type,
    StorageError,
    StorageNotFoundError
)
from backend.utils.station import load_station
from backend.utils.file_helpers import (
    get_case_folder,
    build_case_name_from_registered
)

complaints_bp = Blueprint("complaints", __name__)

ALLOWED_AUDIO_EXTENSIONS = {".webm", ".wav", ".mp3", ".m4a", ".ogg", ".opus", ".flac", ".mp4"}
BLOCKED_PATH_COMPONENTS = {".env", "complaints.db", "backups", ".flask_session", "instance", "backend", "frontend", "tests", "scratch", "templates"}


def is_or_has_symlink(path_to_check: Union[str, Path], base_dir: Path) -> bool:
    """
    Inspect a path and all its ancestor components for symbolic links
    without resolving them first.
    Rejects:
    - Symlinks pointing inside approved directories.
    - Symlinks pointing outside approved directories.
    - Symlinked parent directories in the requested path.
    Fails closed: returns True if inspection fails due to an error.
    """
    try:
        p = Path(path_to_check)
        chk = p if p.is_absolute() else (base_dir / p)
        norm_base = str(base_dir).rstrip("\\/").lower()
        curr = chk
        while curr and curr != curr.parent:
            if curr.is_symlink() or os.path.islink(curr):
                return True
            if curr == base_dir or str(curr).rstrip("\\/").lower() == norm_base:
                break
            curr = curr.parent
        return False
    except (OSError, ValueError):
        # Fail closed: treat inspection errors as unsafe
        return True



@complaints_bp.route("/record", endpoint="record")
@require_role("admin", "officer")
def record():
    """Render the voice recording and audio upload interface."""
    return render_template("record.html")


@complaints_bp.route("/process", methods=["POST"], endpoint="process")
@require_role("admin", "officer")
def process():
    """
    Process incoming audio input, transcribe, generate formal complaint,
    translate, generate PDFs, and save case record.
    """
    complainant_name = request.form["complainant_name"]
    phone_number = request.form["phone_number"]
    complainant_name_telugu = english_to_telugu(complainant_name)

    # Determine audio source (upload vs live recording)
    if "audio" in request.files and request.files["audio"].filename != "":
        audio = request.files["audio"]
    else:
        audio = request.files.get("recorded_audio")

    if not audio:
        return render_template(
            "error.html",
            message="No audio file was received. Please record audio or upload an audio file."
        )

    filename = audio.filename or "recorded.webm"

    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    path = os.path.join(Config.UPLOAD_FOLDER, filename)
    audio.save(path)

    registered_on = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    try:
        text = speech_to_text(path)
        cleaned_text = clean_speech(text)
        complaint = generate_complaint(cleaned_text, complainant_name_telugu)
        english = translate_to_english(complaint, complainant_name)
        subject = generate_subject(complaint)
    except ValueError as e:
        return render_template(
            "error.html",
            message=str(e)
        )
    except Exception as e:
        return render_template(
            "error.html",
            message="Unable to process the audio. Please upload a valid audio file or record again."
        )

    complaint_id = save_complaint(
        registered_on,
        complainant_name,
        complainant_name_telugu,
        phone_number,
        subject,
        filename,
        complaint,
        english
    )

    # SEC-03 Fix: Store only the integer complaint ID in the authenticated session
    session["latest_complaint_id"] = complaint_id

    # Record complaint drafting audit log
    officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=officer.get("id"),
        username=officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action="COMPLAINT_CREATED",
        resource=f"complaints/{complaint_id}",
        status="SUCCESS",
        details=f"Drafted complaint for '{complainant_name}' - Subject: '{subject}'",
        db_path=current_app.config.get("DATABASE_PATH")
    )

    # -----------------------------
    # Create Case Record Folder & Files Locally
    # -----------------------------
    case_folder, case_folder_name = get_case_folder(complaint_id, complainant_name)

    extension = os.path.splitext(filename)[1] or ".webm"
    audio_name = f"Complaint_Audio{extension}"
    audio_destination = case_folder / audio_name

    shutil.copy2(path, str(audio_destination))

    # -----------------------------
    # Generate PDFs
    # -----------------------------
    os.makedirs(Config.GENERATED_FOLDER, exist_ok=True)

    telugu_pdf = case_folder / "Complaint_Telugu.pdf"
    try:
        generate_telugu_pdf(str(telugu_pdf), complaint_id)
    except Exception as e:
        current_app.logger.error(
            f"Failed to generate Telugu PDF for complaint #{complaint_id}: {type(e).__name__}"
        )

    english_pdf = case_folder / "Complaint_English.pdf"
    try:
        generate_english_pdf(str(english_pdf), complaint_id)
    except Exception as e:
        current_app.logger.error(
            f"Failed to generate English PDF for complaint #{complaint_id}: {type(e).__name__}"
        )

    # -----------------------------
    # Storage Backend Persistence
    # -----------------------------
    backend_mode = (Config.STORAGE_BACKEND or "local").strip().lower()

    if backend_mode == "supabase":
        try:
            storage_service = get_storage_service("supabase")
        except Exception as e:
            return render_template(
                "error.html",
                message=f"Storage configuration error: {str(e)}"
            ), 500

        audio_key = build_storage_key(complaint_id, "audio", audio_name)
        telugu_pdf_key = build_storage_key(complaint_id, "pdf", "Complaint_Telugu.pdf")
        english_pdf_key = build_storage_key(complaint_id, "pdf", "Complaint_English.pdf")

        uploaded_keys = []
        try:
            # Upload audio
            storage_service.save_file(audio_destination, audio_key)
            uploaded_keys.append(audio_key)

            # Upload Telugu PDF if generated
            stored_telugu_key = None
            if telugu_pdf.exists() and telugu_pdf.stat().st_size > 0:
                storage_service.save_file(telugu_pdf, telugu_pdf_key)
                uploaded_keys.append(telugu_pdf_key)
                stored_telugu_key = telugu_pdf_key

            # Upload English PDF if generated
            stored_english_key = None
            if english_pdf.exists() and english_pdf.stat().st_size > 0:
                storage_service.save_file(english_pdf, english_pdf_key)
                uploaded_keys.append(english_pdf_key)
                stored_english_key = english_pdf_key

            # Record cloud storage keys in database
            update_complaint_storage(
                complaint_id=complaint_id,
                storage_backend="supabase",
                audio_path=audio_key,
                telugu_pdf_path=stored_telugu_key,
                english_pdf_path=stored_english_key
            )
        except Exception as e:
            # Rollback any partially uploaded objects in Supabase
            for key in uploaded_keys:
                try:
                    storage_service.delete_file(key)
                except Exception:
                    pass
            # Local files are preserved in case_folder as safe fallback
            return render_template(
                "error.html",
                message="Failed to persist complaint files to cloud storage. Please check connection and try again."
            ), 500
    else:
        # Default: Local storage backend
        local_audio_rel = str(audio_destination).replace("\\", "/")
        local_telugu_rel = str(telugu_pdf).replace("\\", "/") if (telugu_pdf.exists() and telugu_pdf.stat().st_size > 0) else None
        local_english_rel = str(english_pdf).replace("\\", "/") if (english_pdf.exists() and english_pdf.stat().st_size > 0) else None

        update_complaint_storage(
            complaint_id=complaint_id,
            storage_backend="local",
            audio_path=local_audio_rel,
            telugu_pdf_path=local_telugu_rel,
            english_pdf_path=local_english_rel
        )

    station = load_station()


    return render_template(
        "result.html",
        complaint_id=complaint_id,
        speech=text,
        complaint=complaint,
        subject=subject,
        complainant_name=complainant_name_telugu,
        phone_number=phone_number,
        station_name=station["station_name"],
        place=station["place"],
        district=station["district"],
        station_name_telugu=station["station_name_telugu"],
        place_telugu=station["place_telugu"],
        district_telugu=station["district_telugu"],
        current_date=datetime.now().strftime("%d-%m-%Y"),
        case_name=case_folder_name
    )


@complaints_bp.route("/english", endpoint="english")
@require_login
def english_page():
    """
    Display the most recently generated English complaint for the current user session.
    SEC-03 remediation: Retrieves complaint strictly from the authenticated session
    and database, eliminating global cross-session data leakage.
    """
    complaint_id = session.get("latest_complaint_id")
    if not complaint_id:
        return render_template(
            "error.html",
            message="No recent complaint found in this session. Please select a complaint from the dashboard."
        )

    try:
        complaint_id_int = int(complaint_id)
    except (ValueError, TypeError):
        return render_template(
            "error.html",
            message="Invalid complaint identifier in current session."
        )

    return view_english(complaint_id_int)


@complaints_bp.route("/view_telugu/<int:complaint_id>", endpoint="view_telugu")
@require_login
def view_telugu(complaint_id):
    """Render formal Telugu complaint page suitable for viewing or printing."""
    db_path = current_app.config.get("DATABASE_PATH") if current_app else None
    complaint = get_complaint_by_id(complaint_id, db_path=db_path)
    if not complaint:
        return render_template("error.html", message="Complaint record not found.")

    station = load_station()
    case_name = build_case_name_from_registered(complaint[0], complaint[2], complaint[1])

    return render_template(
        "result.html",
        complaint=complaint[7],
        subject=complaint[5],
        complainant_name=complaint[3],
        phone_number=complaint[4],
        station_name=station["station_name"],
        place=station["place"],
        district=station["district"],
        station_name_telugu=station["station_name_telugu"],
        place_telugu=station["place_telugu"],
        district_telugu=station["district_telugu"],
        current_date=datetime.now().strftime("%d-%m-%Y"),
        complaint_id=complaint_id,
        case_name=case_name
    )


@complaints_bp.route("/view_english/<int:complaint_id>", endpoint="view_english")
@require_login
def view_english(complaint_id):
    """Render formal English complaint page suitable for viewing or printing."""
    db_path = current_app.config.get("DATABASE_PATH") if current_app else None
    complaint = get_complaint_by_id(complaint_id, db_path=db_path)
    if not complaint:
        return render_template("error.html", message="Complaint record not found.")

    station = load_station()
    case_name = build_case_name_from_registered(complaint[0], complaint[2], complaint[1])

    return render_template(
        "english.html",
        english=complaint[8],
        subject=translate_subject(complaint[5]),
        complainant_name=complaint[2],
        phone_number=complaint[4],
        current_date=datetime.now().strftime("%d-%m-%Y"),
        station_name=station["station_name"],
        place=station["place"],
        district=station["district"],
        case_name=case_name
    )


@complaints_bp.route("/case_audio/<path:filepath>", endpoint="serve_case_audio")
@require_login
def serve_case_audio(filepath):
    """
    Secure case audio streaming endpoint for in-browser audio playback.

    Security constraints:
    1. Authenticated officers/viewers only (@require_login).
    2. Path traversal defense: blocks '..' and leading slashes.
    3. Rejects sensitive project resources (.env, complaints.db, backups, session files).
    4. Validates expected audio extensions (.webm, .wav, .mp3, etc.).
    5. Database verification: requested audio must be associated with a valid complaint record.
    6. Directory jail & symlink defense: resolved file must reside within approved audio folders.
    7. Supports direct complaint ID lookup (/case_audio/<int:id>) for robust access.
    """
    raw_input = filepath.strip()
    db_path = current_app.config.get("DATABASE_PATH") if current_app else None

    # Immediate rejection of directory traversal syntax
    if ".." in raw_input or raw_input.startswith("/") or raw_input.startswith("\\"):
        return render_template("error.html", message="Invalid path format."), 400

    target_complaint = None

    # Mode 1: Integer complaint ID supplied (/case_audio/<int:id>)
    if raw_input.isdigit():
        target_complaint = get_complaint_by_id(int(raw_input), db_path=db_path)
        if not target_complaint:
            return render_template("error.html", message="Complaint audio not found."), 404
    else:
        # Mode 2: File path supplied
        # Step A: Validate extension
        ext = os.path.splitext(raw_input)[1].lower()
        if not ext or ext not in ALLOWED_AUDIO_EXTENSIONS:
            return render_template("error.html", message="Invalid audio file extension."), 400

        # Step B: Block sensitive files or folders explicitly
        normalized_parts = [p.lower() for p in re.split(r"[\\/]", raw_input)]
        for blocked in BLOCKED_PATH_COMPONENTS:
            if blocked in normalized_parts or any(blocked in part for part in normalized_parts):
                return render_template("error.html", message="Access denied to restricted resource."), 403

        # Step B.2: Reject symbolic links in requested path components immediately
        base_dir = Path(Config.BASE_DIR).resolve()
        if is_or_has_symlink(raw_input, base_dir):
            return render_template("error.html", message="Access denied: symbolic links are not permitted."), 403

        # Step C: Verify file belongs to an active complaint in SQLite database
        normalized_input = raw_input.replace("\\", "/").lstrip("/")
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, audio_path FROM complaints")
            all_complaints = cursor.fetchall()
            for row in all_complaints:
                cid, apath = row[0], row[1]
                if not apath:
                    continue
                norm_apath = apath.strip().replace("\\", "/").lstrip("/")
                if (norm_apath == normalized_input or
                    norm_apath.endswith(normalized_input) or
                    normalized_input.endswith(norm_apath)):
                    target_complaint = get_complaint_by_id(cid, db_path=db_path)
                    break
        finally:
            conn.close()

        if not target_complaint:
            return render_template("error.html", message="Audio file is not associated with any valid complaint."), 404

    complaint_id = target_complaint[0]
    storage_info = get_complaint_storage_info(complaint_id) or {}
    backend_type = storage_info.get("storage_backend", "local")
    target_key = storage_info.get("audio_path") or target_complaint[6]

    if not target_key:
        return render_template("error.html", message="Audio file not configured for this complaint."), 404

    # Cloud retrieval (Supabase)
    if backend_type == "supabase":
        try:
            storage_service = get_storage_service("supabase")
            stream = storage_service.get_file_stream(target_key)
            content_type = get_content_type(target_key)

            officer = getattr(g, "current_officer", {})
            create_audit_log(
                officer_id=officer.get("id"),
                username=officer.get("username"),
                ip_address=request.remote_addr or "unknown",
                action="FILE_ACCESSED",
                resource=f"case_audio/{complaint_id}",
                status="SUCCESS",
                details=f"Streamed cloud audio for complaint #{complaint_id}",
                db_path=db_path
            )
            return send_file(stream, mimetype=content_type)
        except Exception:
            return render_template("error.html", message="Unable to stream audio from cloud storage."), 500

    # Local filesystem retrieval
    base_dir = Path(Config.BASE_DIR).resolve()
    approved_roots = [
        (base_dir / Config.CASE_RECORDS_FOLDER).resolve(),
        (base_dir / Config.UPLOAD_FOLDER).resolve(),
        (base_dir / "audio").resolve()
    ]

    target_path = Path(target_key)
    candidate_path = (base_dir / target_key) if not target_path.is_absolute() else target_path

    # Symlink defense: inspect candidate path and all parent components BEFORE resolving
    if is_or_has_symlink(candidate_path, base_dir):
        return render_template("error.html", message="Access denied: symbolic links are not permitted."), 403

    resolved_file = candidate_path.resolve()

    # Symlink and directory jail check:
    # Target file (with all symlinks fully resolved) MUST reside within an approved audio folder
    is_inside_approved = False
    for root in approved_roots:
        try:
            resolved_file.relative_to(root)
            is_inside_approved = True
            break
        except ValueError:
            continue

    if not is_inside_approved:
        return render_template("error.html", message="Access denied: file outside approved audio storage."), 403

    if not resolved_file.exists() or not resolved_file.is_file():
        return render_template("error.html", message="Audio file not found on disk."), 404

    file_ext = resolved_file.suffix.lower()
    if file_ext not in ALLOWED_AUDIO_EXTENSIONS:
        return render_template("error.html", message="Invalid audio file type."), 400

    content_type = get_content_type(resolved_file.name)
    officer = getattr(g, "current_officer", {})
    create_audit_log(
        officer_id=officer.get("id"),
        username=officer.get("username"),
        ip_address=request.remote_addr or "unknown",
        action="FILE_ACCESSED",
        resource=f"case_audio/{complaint_id}",
        status="SUCCESS",
        details=f"Streamed local case audio for complaint #{complaint_id}",
        db_path=db_path
    )
    return send_file(resolved_file, mimetype=content_type)


@complaints_bp.route("/complaints/<int:complaint_id>/files/<file_type>", endpoint="download_file")
@require_login
def download_file(complaint_id: int, file_type: str):
    """
    Secure file retrieval endpoint for complaint audio and PDF files.
    Validates complaint existence, validates file type, and routes through
    the appropriate storage backend (local filesystem or private Supabase bucket).

    Supported file_type: 'audio', 'telugu_pdf', 'english_pdf'.
    Optional query params:
        mode: 'signed_url' (redirects to short-lived signed URL for Supabase)
              or 'stream' (default: authenticated backend byte streaming)
        download: 'true' (sets Content-Disposition: attachment)

    SECURITY LIMITATION NOTE:
    The application currently lacks authentication (session/token auth for police personnel).
    In production, this route MUST be guarded by role-based authentication to protect private citizen records.
    """
    allowed_types = ("audio", "telugu_pdf", "english_pdf")
    if file_type not in allowed_types:
        return render_template("error.html", message=f"Invalid file type requested: {file_type}"), 400

    complaint = get_complaint_by_id(complaint_id)
    if not complaint:
        return render_template("error.html", message="Complaint record not found."), 404

    storage_info = get_complaint_storage_info(complaint_id) or {}
    backend_type = storage_info.get("storage_backend", "local")

    target_key = None
    default_filename = f"Complaint_{file_type}"
    if file_type == "audio":
        target_key = storage_info.get("audio_path")
        ext = os.path.splitext(target_key or "")[1] or ".webm"
        default_filename = f"Complaint_Audio{ext}"
    elif file_type == "telugu_pdf":
        target_key = storage_info.get("telugu_pdf_path")
        default_filename = "Complaint_Telugu.pdf"
    elif file_type == "english_pdf":
        target_key = storage_info.get("english_pdf_path")
        default_filename = "Complaint_English.pdf"

    # Cloud retrieval (Supabase)
    if backend_type == "supabase" and target_key:
        try:
            storage_service = get_storage_service("supabase")
            mode = request.args.get("mode", "stream").strip().lower()
            if mode == "signed_url":
                signed_url = storage_service.get_signed_url(target_key, expires_in=900)
                officer = getattr(g, "current_officer", {})
                create_audit_log(
                    officer_id=officer.get("id"),
                    username=officer.get("username"),
                    ip_address=request.remote_addr or "unknown",
                    action="SIGNED_URL_GENERATED",
                    resource=f"complaints/{complaint_id}/files/{file_type}",
                    status="SUCCESS",
                    details=f"Generated 900s signed URL for {file_type} of complaint #{complaint_id}",
                    db_path=current_app.config.get("DATABASE_PATH")
                )
                return redirect(signed_url)

            stream = storage_service.get_file_stream(target_key)
            content_type = get_content_type(target_key)
            as_attachment = request.args.get("download", "false").lower() == "true"

            officer = getattr(g, "current_officer", {})
            create_audit_log(
                officer_id=officer.get("id"),
                username=officer.get("username"),
                ip_address=request.remote_addr or "unknown",
                action="FILE_ACCESSED",
                resource=f"complaints/{complaint_id}/files/{file_type}",
                status="SUCCESS",
                details=f"Streamed cloud {file_type} for complaint #{complaint_id}",
                db_path=current_app.config.get("DATABASE_PATH")
            )

            return send_file(
                stream,
                mimetype=content_type,
                as_attachment=as_attachment,
                download_name=default_filename
            )
        except Exception:
            return render_template(
                "error.html",
                message="Unable to retrieve the requested file from cloud storage."
            ), 500

    # Local filesystem retrieval (or fallback for older rows)
    if not target_key:
        complainant_name = complaint[2] or "Citizen"
        registered_on = complaint[1]
        case_name = build_case_name_from_registered(complaint_id, complainant_name, registered_on)
        case_dirs = list(Path(Config.CASE_RECORDS_FOLDER).glob(f"**/{case_name}"))
        if case_dirs:
            candidate = case_dirs[0] / default_filename
            if candidate.exists():
                target_key = str(candidate)

    if not target_key:
        return render_template("error.html", message="Requested file is not available."), 404

    try:
        base_dir = Path(Config.BASE_DIR).resolve()
        file_path = Path(target_key)
        if not file_path.is_absolute():
            file_path = (base_dir / target_key).resolve()
        else:
            file_path = file_path.resolve()

        file_path.relative_to(base_dir)
        if not file_path.exists() or not file_path.is_file():
            return render_template("error.html", message="Local file not found."), 404

        content_type = get_content_type(file_path.name)
        as_attachment = request.args.get("download", "false").lower() == "true"

        officer = getattr(g, "current_officer", {})
        create_audit_log(
            officer_id=officer.get("id"),
            username=officer.get("username"),
            ip_address=request.remote_addr or "unknown",
            action="FILE_ACCESSED",
            resource=f"complaints/{complaint_id}/files/{file_type}",
            status="SUCCESS",
            details=f"Served local {file_type} for complaint #{complaint_id}",
            db_path=current_app.config.get("DATABASE_PATH")
        )

        return send_file(
            file_path,
            mimetype=content_type,
            as_attachment=as_attachment,
            download_name=default_filename
        )
    except (ValueError, StorageError):
        return render_template("error.html", message="Invalid file path."), 400

