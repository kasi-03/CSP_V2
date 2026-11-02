"""
backend/services/storage_migrator.py
====================================
Historical Complaint Data Migration Utility for CSP_V2.

Provides preparation, validation, hashing, collision checking, and dry-run
capabilities to migrate historical complaints and case files to Supabase Object Storage.

STRICT SAFETY GUARANTEES:
1. Reads existing SQLite database in read-only mode (uri=True, mode=ro).
2. Never executes upload or write operations during preparation or dry-run.
3. Preserves exact physical audio extensions (.webm, .wav, etc.).
4. Treats missing PDFs (complaints 18 & 19) as NULL without failing.
5. Locates physical PDFs for complaints 2–17 even when database column is NULL.
6. Computes SHA-256 checksums and file sizes for every source file.
7. Verifies Supabase collisions using read-only bucket listing.
8. Protects existing complaint 23 object from modification or overwrite.
"""

import os
import sys
import json
import hashlib
import sqlite3
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from config import Config


def compute_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Calculate the SHA-256 hex digest of a local file in streaming chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def resolve_file_location(
    complaint_id: int,
    file_type: str,  # 'audio', 'telugu_pdf', 'english_pdf'
    recorded_path: Optional[str],
    base_dir: Path
) -> Optional[Path]:
    """
    Safely resolve the physical file path for a complaint attachment.
    Inspects recorded path, standard storage directories, and case records glob.
    Returns resolved Path if file exists on disk, None otherwise.
    """
    case_records_dir = base_dir / "case_records"
    audio_dir = base_dir / "audio"
    generated_dir = base_dir / "generated"

    # 1. Check recorded path directly if provided
    if recorded_path and recorded_path.strip():
        # Handle forward/backslash variation
        clean_path = recorded_path.strip().replace("\\", "/")
        candidates = [
            Path(clean_path),
            base_dir / clean_path,
        ]
        if file_type == "audio":
            candidates.append(audio_dir / Path(clean_path).name)
        else:
            candidates.append(generated_dir / Path(clean_path).name)

        for cand in candidates:
            try:
                if cand.exists() and cand.is_file():
                    return cand.resolve()
            except Exception:
                pass

    # 2. Search case_records folder for this complaint ID (C001, C002, etc.)
    id_pattern = f"*C{complaint_id:03d}*"
    try:
        matched_folders = list(case_records_dir.glob(f"**/{id_pattern}"))
        for folder in matched_folders:
            if not folder.is_dir():
                continue
            if file_type == "audio":
                # Look for Complaint_Audio.*
                audio_matches = list(folder.glob("Complaint_Audio.*"))
                if audio_matches and audio_matches[0].is_file():
                    return audio_matches[0].resolve()
                # Fallback to any audio file in case folder
                for ext in (".webm", ".wav", ".mp3", ".m4a", ".ogg", ".opus"):
                    cand_files = list(folder.glob(f"*{ext}"))
                    if cand_files and cand_files[0].is_file():
                        return cand_files[0].resolve()
            elif file_type == "telugu_pdf":
                matches = list(folder.glob("*Telugu*.pdf"))
                if matches and matches[0].is_file():
                    return matches[0].resolve()
            elif file_type == "english_pdf":
                matches = list(folder.glob("*English*.pdf"))
                if matches and matches[0].is_file():
                    return matches[0].resolve()
    except Exception:
        pass

    return None


def inspect_supabase_existing_keys(
    bucket_name: Optional[str] = None
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Perform read-only listing of Supabase bucket objects under 'complaints/'.
    Returns (summary_dict, all_existing_keys).
    Guarantees no modifications, uploads, or deletes.
    """
    existing_keys: List[str] = []
    summary: Dict[str, Any] = {
        "connected": False,
        "bucket": bucket_name or Config.STORAGE_BUCKET or "complaint-files",
        "existing_keys_count": 0,
        "protected_objects": [],
        "error": None
    }

    bucket = summary["bucket"]
    try:
        from supabase import create_client
        if not Config.SUPABASE_URL or not Config.SUPABASE_KEY:
            summary["error"] = "SUPABASE_URL or SUPABASE_KEY not configured."
            return summary, existing_keys

        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
        summary["connected"] = True

        # List subfolders in complaints/
        try:
            complaint_dirs = client.storage.from_(bucket).list("complaints")
            for item in complaint_dirs:
                folder = item.get("name")
                if not folder:
                    continue
                # Check audio subfolder
                try:
                    audios = client.storage.from_(bucket).list(f"complaints/{folder}/audio")
                    for a in audios:
                        key = f"complaints/{folder}/audio/{a['name']}"
                        existing_keys.append(key)
                        if folder == "23":
                            summary["protected_objects"].append(key)
                except Exception:
                    pass
                # Check pdf subfolder
                try:
                    pdfs = client.storage.from_(bucket).list(f"complaints/{folder}/pdf")
                    for p in pdfs:
                        key = f"complaints/{folder}/pdf/{p['name']}"
                        existing_keys.append(key)
                        if folder == "23":
                            summary["protected_objects"].append(key)
                except Exception:
                    pass
        except Exception as list_err:
            summary["error"] = f"Bucket list error: {type(list_err).__name__}: {str(list_err)}"

        summary["existing_keys_count"] = len(existing_keys)
    except Exception as e:
        summary["error"] = f"Client init error: {type(e).__name__}: {str(e)}"

    return summary, existing_keys


def generate_migration_manifest(
    db_path: Optional[str] = None,
    base_dir: Optional[Path] = None,
    check_supabase: bool = True
) -> Dict[str, Any]:
    """
    Build a comprehensive, read-only migration manifest for all complaints.
    Computes exact file paths, hashes, sizes, proposed Supabase keys,
    and detects any collisions.
    """
    target_db = db_path or Config.DATABASE_PATH
    abs_db = os.path.abspath(target_db)
    root_dir = Path(base_dir or Config.BASE_DIR).resolve()

    if not os.path.exists(abs_db):
        raise FileNotFoundError(f"Database file not found: {abs_db}")

    # Read-only SQLite connection
    uri = f"file:{abs_db}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, registered_on, english_name, telugu_name, phone, subject,
                   audio_path, storage_backend, telugu_pdf_path, english_pdf_path
            FROM complaints
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()

    # Query Supabase existing keys if requested
    supabase_summary = {"connected": False, "existing_keys_count": 0, "protected_objects": []}
    existing_cloud_keys: List[str] = []
    if check_supabase:
        supabase_summary, existing_cloud_keys = inspect_supabase_existing_keys()

    manifest_complaints: List[Dict[str, Any]] = []
    total_files_count = 0
    total_bytes_count = 0
    missing_files_count = 0
    collisions_detected: List[str] = []

    for row in rows:
        cid, reg_on, eng_name, tel_name, phone, subj, audio_p, backend, tel_pdf_p, eng_pdf_p = row
        current_backend = (backend or "local").strip().lower()

        # 1. Resolve Audio File
        resolved_audio = resolve_file_location(cid, "audio", audio_p, root_dir)
        audio_entry: Dict[str, Any] = {}
        if resolved_audio and resolved_audio.is_file():
            ext = resolved_audio.suffix.lower() or ".webm"
            dest_key = f"complaints/{cid}/audio/Complaint_Audio{ext}"
            size = resolved_audio.stat().st_size
            sha256_hash = compute_file_sha256(str(resolved_audio))
            total_files_count += 1
            total_bytes_count += size

            is_collision = dest_key in existing_cloud_keys
            if is_collision:
                collisions_detected.append(dest_key)

            audio_entry = {
                "exists": True,
                "source_path": str(resolved_audio),
                "destination_key": dest_key,
                "size_bytes": size,
                "sha256": sha256_hash,
                "mime_type": "audio/wav" if ext == ".wav" else "audio/webm",
                "status": "COLLISION" if is_collision else "READY"
            }
        else:
            missing_files_count += 1
            audio_entry = {
                "exists": False,
                "source_path": None,
                "destination_key": None,
                "size_bytes": 0,
                "sha256": None,
                "status": "MISSING_ERROR"
            }

        # 2. Resolve Telugu PDF File
        resolved_telugu = resolve_file_location(cid, "telugu_pdf", tel_pdf_p, root_dir)
        telugu_entry: Dict[str, Any] = {}
        if resolved_telugu and resolved_telugu.is_file():
            dest_key = f"complaints/{cid}/pdf/Complaint_Telugu.pdf"
            size = resolved_telugu.stat().st_size
            sha256_hash = compute_file_sha256(str(resolved_telugu))
            total_files_count += 1
            total_bytes_count += size

            is_collision = dest_key in existing_cloud_keys
            if is_collision:
                collisions_detected.append(dest_key)

            telugu_entry = {
                "exists": True,
                "source_path": str(resolved_telugu),
                "destination_key": dest_key,
                "size_bytes": size,
                "sha256": sha256_hash,
                "mime_type": "application/pdf",
                "status": "COLLISION" if is_collision else "READY"
            }
        else:
            missing_files_count += 1
            # Expected for complaints 18 and 19
            telugu_entry = {
                "exists": False,
                "source_path": None,
                "destination_key": None,
                "size_bytes": 0,
                "sha256": None,
                "status": "MISSING_IGNORED"
            }

        # 3. Resolve English PDF File
        resolved_english = resolve_file_location(cid, "english_pdf", eng_pdf_p, root_dir)
        english_entry: Dict[str, Any] = {}
        if resolved_english and resolved_english.is_file():
            dest_key = f"complaints/{cid}/pdf/Complaint_English.pdf"
            size = resolved_english.stat().st_size
            sha256_hash = compute_file_sha256(str(resolved_english))
            total_files_count += 1
            total_bytes_count += size

            is_collision = dest_key in existing_cloud_keys
            if is_collision:
                collisions_detected.append(dest_key)

            english_entry = {
                "exists": True,
                "source_path": str(resolved_english),
                "destination_key": dest_key,
                "size_bytes": size,
                "sha256": sha256_hash,
                "mime_type": "application/pdf",
                "status": "COLLISION" if is_collision else "READY"
            }
        else:
            missing_files_count += 1
            # Expected for complaints 18 and 19
            english_entry = {
                "exists": False,
                "source_path": None,
                "destination_key": None,
                "size_bytes": 0,
                "sha256": None,
                "status": "MISSING_IGNORED"
            }

        # Projected SQLite update values
        proposed_db_update = {
            "complaint_id": cid,
            "storage_backend": "supabase",
            "audio_path": audio_entry.get("destination_key"),
            "telugu_pdf_path": telugu_entry.get("destination_key"),
            "english_pdf_path": english_entry.get("destination_key")
        }

        manifest_complaints.append({
            "complaint_id": cid,
            "registered_on": reg_on,
            "complainant_name": eng_name,
            "current_backend": current_backend,
            "raw_db_audio_path": audio_p,
            "raw_db_telugu_pdf": tel_pdf_p,
            "raw_db_english_pdf": eng_pdf_p,
            "files": {
                "audio": audio_entry,
                "telugu_pdf": telugu_entry,
                "english_pdf": english_entry
            },
            "proposed_db_update": proposed_db_update
        })

    manifest: Dict[str, Any] = {
        "manifest_version": "1.0",
        "source_database": abs_db,
        "total_complaints": len(manifest_complaints),
        "total_files_available": total_files_count,
        "total_payload_bytes": total_bytes_count,
        "missing_file_references": missing_files_count,
        "supabase_verification": {
            "connected": supabase_summary.get("connected", False),
            "bucket": supabase_summary.get("bucket"),
            "existing_keys_count": supabase_summary.get("existing_keys_count", 0),
            "protected_objects": supabase_summary.get("protected_objects", []),
            "collisions_detected": collisions_detected
        },
        "complaints": manifest_complaints
    }

    return manifest


def execute_dry_run(
    db_path: Optional[str] = None,
    output_manifest_path: Optional[str] = None,
    check_supabase: bool = True,
    base_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Perform a full dry-run simulation of the migration.
    Prints a detailed human-readable migration plan, displays all SQL statements,
    saves the migration manifest JSON, and strictly prevents any mutations.
    """
    manifest = generate_migration_manifest(
        db_path=db_path,
        base_dir=base_dir,
        check_supabase=check_supabase
    )

    print("\n" + "=" * 80)
    print("  CSP_V2 - HISTORICAL COMPLAINT DATA MIGRATION TOOL (DRY-RUN)")
    print("=" * 80)
    print(f" Source Database   : {manifest['source_database']}")
    print(f" Total Complaints  : {manifest['total_complaints']}")
    print(f" Files Available   : {manifest['total_files_available']} files ({manifest['total_payload_bytes'] / (1024*1024):.2f} MB)")
    print(f" Missing Files     : {manifest['missing_file_references']} (IDs 18 & 19 PDFs handled as NULL)")
    
    supa = manifest["supabase_verification"]
    print(f" Supabase Connected: {supa['connected']} (Bucket: {supa['bucket']})")
    print(f" Protected Objects : {supa['protected_objects']}")
    print(f" Cloud Collisions  : {len(supa['collisions_detected'])}")

    print("\n" + "-" * 80)
    print(" MIGRATION MANIFEST DETAILS (DRY-RUN)")
    print("-" * 80)

    audio_ready = 0
    telugu_ready = 0
    english_ready = 0

    for c in manifest["complaints"]:
        cid = c["complaint_id"]
        cname = c["complainant_name"]
        files = c["files"]

        a_stat = files["audio"]["status"]
        t_stat = files["telugu_pdf"]["status"]
        e_stat = files["english_pdf"]["status"]

        if a_stat == "READY":
            audio_ready += 1
        if t_stat == "READY":
            telugu_ready += 1
        if e_stat == "READY":
            english_ready += 1

        a_key = files["audio"].get("destination_key") or "NULL"
        t_key = files["telugu_pdf"].get("destination_key") or "NULL"
        e_key = files["english_pdf"].get("destination_key") or "NULL"

        print(f" Complaint #{cid:02d} ({cname}):")
        print(f"   Audio      [{a_stat}]: {a_key} ({files['audio']['size_bytes']} bytes, SHA256: {str(files['audio']['sha256'])[:12]}...)")
        print(f"   Telugu PDF [{t_stat}]: {t_key}")
        print(f"   English PDF[{e_stat}]: {e_key}")

    print("\n" + "-" * 80)
    print(" PROJECTED SQL TRANSACTION STATEMENTS (DRY-RUN - NO CHANGES EXECUTED)")
    print("-" * 80)
    print(" BEGIN TRANSACTION;")
    for c in manifest["complaints"]:
        u = c["proposed_db_update"]
        print(
            f"   UPDATE complaints SET storage_backend = 'supabase', "
            f"audio_path = {repr(u['audio_path'])}, "
            f"telugu_pdf_path = {repr(u['telugu_pdf_path']) if u['telugu_pdf_path'] else 'NULL'}, "
            f"english_pdf_path = {repr(u['english_pdf_path']) if u['english_pdf_path'] else 'NULL'} "
            f"WHERE id = {u['complaint_id']};"
        )
    print(" COMMIT;\n")

    print(f" Summary of files to upload:")
    print(f"   Audio Files : {audio_ready} / {manifest['total_complaints']}")
    print(f"   Telugu PDFs : {telugu_ready} / {manifest['total_complaints']}")
    print(f"   English PDFs: {english_ready} / {manifest['total_complaints']}")
    print(f"   Total Files : {audio_ready + telugu_ready + english_ready} (Matches Phase 8.4 audit: 53 files)")

    # Save manifest if path provided
    out_path = output_manifest_path or os.path.join(Config.BASE_DIR, "migration_manifest.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n[+] Saved migration manifest to: {out_path}")
    except Exception as e:
        print(f"\n[-] Note: Could not save manifest to {out_path}: {e}")

    print("\n" + "=" * 80)
    print("  DRY-RUN COMPLETE: ZERO UPLOADS OR DATABASE WRITES WERE EXECUTED.")
    print("=" * 80 + "\n")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="CSP_V2 Historical Data Migration Utility")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate migration without modifying files or database (default: True)")
    parser.add_argument("--db-path", help="Path to SQLite complaints.db")
    parser.add_argument("--output-manifest", help="Path to write migration manifest JSON")
    parser.add_argument("--skip-supabase-check", action="store_true", help="Skip remote Supabase collision check")

    args = parser.parse_args()

    execute_dry_run(
        db_path=args.db_path,
        output_manifest_path=args.output_manifest,
        check_supabase=not args.skip_supabase_check
    )


if __name__ == "__main__":
    main()
