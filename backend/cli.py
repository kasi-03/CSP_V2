"""
Command-Line Interface for CSP_V2 Administration.

Provides secure manual provisioning of the first Administrator account:
    python -m backend.cli create-admin
"""

import sys
import os
import hashlib
import sqlite3
import getpass
import argparse
from typing import Optional

from config import Config
from backend.services.database import (
    init_db,
    get_officer_by_username,
    get_officers_count,
    create_officer,
    create_audit_log,
    validate_production_database
)
from backend.services.auth import (
    hash_password,
    validate_password_strength
)


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 checksum of a file in 64KB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def snapshot_database(
    source_path: Optional[str] = None,
    target_path: Optional[str] = None,
    force: bool = False
) -> int:
    """
    Safely create a crash-consistent, standalone snapshot of the database using SQLite's Online Backup API.
    Writes to an isolated temporary file first, then atomically replaces the target path.
    Refuses to overwrite an existing target unless --force is specified.
    """
    source = os.path.abspath(source_path or Config.DATABASE_PATH)
    if not target_path:
        print("[-] ERROR: Target snapshot path is required (--target).")
        return -1

    target = os.path.abspath(target_path)

    # 1. Validate source database
    try:
        validate_production_database(source)
    except Exception as e:
        print(f"[-] ERROR: Source database validation failed: {e}")
        return -1

    # 2. Check for target collision
    if os.path.exists(target) and not force:
        print(f"[-] ERROR: Target file already exists at '{target}'.")
        print("    Use --force to explicitly allow overwriting the target snapshot.")
        return -1

    target_dir = os.path.dirname(target)
    if target_dir:
        os.makedirs(target_dir, exist_ok=True)

    temp_target = f"{target}.tmp.{os.getpid()}"

    print("\n" + "=" * 65)
    print("  CSP_V2 - DATABASE SNAPSHOT CREATION")
    print("=" * 65)
    print(f"Source Database : {source}")
    print(f"Target Snapshot : {target}")

    try:
        # 3. Perform Online Backup via SQLite C-API
        src_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        dst_conn = sqlite3.connect(temp_target)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            src_conn.close()

        # 4. Validate temporary target
        validate_production_database(temp_target)

        # 5. Atomic rename
        os.replace(temp_target, target)

        size = os.path.getsize(target)
        sha256 = compute_file_sha256(target)

        print("\n[+] Database snapshot created successfully!")
        print(f"    File Size   : {size:,} bytes")
        print(f"    SHA-256     : {sha256}")
        print("=" * 65 + "\n")
        return 0
    except Exception as e:
        print(f"\n[-] ERROR: Snapshot creation failed: {e}")
        return -1
    finally:
        if os.path.exists(temp_target):
            try:
                os.remove(temp_target)
            except OSError:
                pass


def verify_database(
    db_path: Optional[str] = None,
    expected_complaints: Optional[int] = None,
    expected_officers: Optional[int] = None,
    expected_audit_logs: Optional[int] = None,
    expected_sha256: Optional[str] = None
) -> int:
    """
    Perform a comprehensive, strictly read-only audit of an SQLite database.
    Verifies SQLite integrity, foreign keys, required schema, and active administrator.
    Optionally compares against expected counts/hashes for deployment verification.
    """
    target = os.path.abspath(db_path or Config.DATABASE_PATH)

    print("\n" + "=" * 65)
    print("  CSP_V2 - DATABASE INTEGRITY & READINESS VERIFICATION")
    print("=" * 65)
    print(f"Target Database : {target}")

    # 1. Structural and Administrative Validation
    try:
        validate_production_database(target)
        print("  [PASS] Structural integrity & administrative check: OK")
    except Exception as e:
        print(f"  [FAIL] Validation error: {e}")
        print("=" * 65 + "\n")
        return -1

    # 2. Detailed Read-Only Metrics
    try:
        conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM complaints")
        complaints_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM officers")
        officers_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM officers WHERE role = 'admin' AND is_active = 1")
        active_admins = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        audit_logs_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM login_attempts")
        login_attempts_count = cursor.fetchone()[0]

        conn.close()

        size = os.path.getsize(target)
        sha256 = compute_file_sha256(target)

        print(f"  [INFO] File Size          : {size:,} bytes")
        print(f"  [INFO] SHA-256 Checksum   : {sha256}")
        print(f"  [INFO] Total Complaints   : {complaints_count}")
        print(f"  [INFO] Total Officers     : {officers_count} ({active_admins} active admin)")
        print(f"  [INFO] Audit Log Entries  : {audit_logs_count}")
        print(f"  [INFO] Login Attempts     : {login_attempts_count}")

        # Check expectations if provided
        mismatches = []
        if expected_complaints is not None and complaints_count != expected_complaints:
            mismatches.append(f"Complaints count: expected {expected_complaints}, got {complaints_count}")
        if expected_officers is not None and officers_count != expected_officers:
            mismatches.append(f"Officers count: expected {expected_officers}, got {officers_count}")
        if expected_audit_logs is not None and audit_logs_count < expected_audit_logs:
            mismatches.append(f"Audit logs count: expected >= {expected_audit_logs}, got {audit_logs_count}")
        if expected_sha256 and sha256.lower() != expected_sha256.strip().lower():
            mismatches.append(f"SHA-256 checksum mismatch: expected {expected_sha256.strip().lower()}, got {sha256.lower()}")

        if mismatches:
            print("\n[-] Verification FAILED due to expectation mismatch:")
            for m in mismatches:
                print(f"    - {m}")
            print("=" * 65 + "\n")
            return -1

        print("\n[+] Database verified successfully! Ready for production deployment.")
        print("=" * 65 + "\n")
        return 0
    except Exception as e:
        print(f"\n[-] ERROR: Verification query failed: {e}")
        print("=" * 65 + "\n")
        return -1


def restore_database(
    source_path: str,
    target_path: Optional[str] = None,
    force: bool = False
) -> int:
    """
    Safely restore an existing database snapshot to the target path.
    1. Validates the source database thoroughly before touching target.
    2. Refuses to overwrite an existing target database automatically.
    3. Writes to a temporary target file first via SQLite backup API.
    4. Atomically replaces target once validation succeeds.
    5. Re-validates target after replacement.
    6. Never deletes existing database or WAL/SHM automatically.
    """
    if not source_path:
        print("[-] ERROR: Source snapshot path is required (--source).")
        return -1

    source = os.path.abspath(source_path)
    target = os.path.abspath(target_path or Config.DATABASE_PATH)

    print("\n" + "=" * 65)
    print("  CSP_V2 - DATABASE RESTORE UTILITY")
    print("=" * 65)
    print(f"Source Snapshot : {source}")
    print(f"Target Database : {target}")

    # 1. Pre-validate source
    try:
        validate_production_database(source)
        print("  [PASS] Source snapshot validated successfully.")
    except Exception as e:
        print(f"[-] ERROR: Source snapshot validation failed: {e}")
        return -1

    # 2. Check target collision: refuse to overwrite automatically
    if os.path.exists(target) and not force:
        print(f"[-] ERROR: Target database already exists at '{target}'.")
        print("    Refusing to overwrite an existing production database automatically.")
        print("    To overwrite an existing target database, supply --force explicitly.")
        return -1

    target_dir = os.path.dirname(target)
    if target_dir:
        os.makedirs(target_dir, exist_ok=True)

    temp_target = f"{target}.tmp.{os.getpid()}"

    try:
        # 3. Stream backup to temporary target file
        src_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        dst_conn = sqlite3.connect(temp_target)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            src_conn.close()

        # 4. Validate temporary target file
        validate_production_database(temp_target)

        # 5. Atomic replacement
        os.replace(temp_target, target)

        # 6. Post-restore validation
        validate_production_database(target)

        size = os.path.getsize(target)
        sha256 = compute_file_sha256(target)

        print("\n[+] Database restored successfully!")
        print(f"    Target Location : {target}")
        print(f"    File Size       : {size:,} bytes")
        print(f"    SHA-256 Checksum: {sha256}")
        print("=" * 65 + "\n")
        return 0
    except Exception as e:
        print(f"\n[-] ERROR: Database restoration failed: {e}")
        return -1
    finally:
        if os.path.exists(temp_target):
            try:
                os.remove(temp_target)
            except OSError:
                pass


def create_admin_interactive(
    username: Optional[str] = None,
    full_name: Optional[str] = None,
    password: Optional[str] = None,
    badge_number: Optional[str] = None,
    force: bool = False,
    db_path: Optional[str] = None
) -> int:
    """
    Interactively (or via CLI arguments) create an Administrator account.
    Enforces password complexity, duplicate prevention, and zero hardcoded defaults.
    """
    init_db(db_path)

    print("\n" + "=" * 65)
    print("  CSP_V2 - POLICE SYSTEM ADMINISTRATOR ACCOUNT PROVISIONING")
    print("=" * 65)

    # 1. Check for existing administrators
    admin_count = get_officers_count(role="admin", db_path=db_path)
    if admin_count > 0 and not force:
        print(f"\n[!] WARNING: {admin_count} Administrator account(s) already exist.")
        confirm = input("Are you sure you want to create an additional Administrator? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Operation aborted. No account was created.")
            return -1

    # 2. Get and validate username
    while not username:
        raw_user = input("\nEnter Admin username: ").strip()
        if not raw_user:
            print("Username cannot be empty. Please try again.")
            continue
        if len(raw_user) < 3:
            print("Username must be at least 3 characters long.")
            continue
        username = raw_user

    existing = get_officer_by_username(username, db_path=db_path)
    if existing:
        print(f"\n[-] ERROR: An officer with username '{username}' already exists (case-insensitive).")
        return -1

    # 3. Get Full Name
    while not full_name:
        raw_name = input("Enter Admin full name: ").strip()
        if not raw_name:
            print("Full name cannot be empty. Please try again.")
            continue
        full_name = raw_name

    # 4. Get Badge Number (optional)
    if badge_number is None:
        raw_badge = input("Enter Badge Number / Police ID (optional): ").strip()
        badge_number = raw_badge if raw_badge else None

    # 5. Get and validate password securely
    while not password:
        pwd1 = getpass.getpass("Enter Admin password: ")
        if not pwd1:
            print("Password cannot be empty.")
            continue

        is_valid, msg = validate_password_strength(pwd1)
        if not is_valid:
            print(f"[-] Password does not meet security policy: {msg}")
            print("    Requirements: Min 8 chars, uppercase, lowercase, digit, special symbol.")
            continue

        pwd2 = getpass.getpass("Confirm Admin password: ")
        if pwd1 != pwd2:
            print("[-] Passwords do not match. Please try again.")
            continue

        password = pwd1

    # Final policy validation
    is_valid, msg = validate_password_strength(password)
    if not is_valid:
        print(f"[-] Password rejected: {msg}")
        return -1

    # 6. Hash password with Werkzeug scrypt
    hashed = hash_password(password)

    # 7. Store officer record in database
    officer_id = create_officer(
        username=username,
        password_hash=hashed,
        full_name=full_name,
        role="admin",
        badge_number=badge_number,
        db_path=db_path
    )

    # 8. Record audit log
    create_audit_log(
        officer_id=officer_id,
        username=username,
        ip_address="127.0.0.1",
        action="OFFICER_CREATED",
        resource=f"officers/{officer_id}",
        status="SUCCESS",
        details="Admin account provisioned via CLI",
        db_path=db_path
    )

    print("\n" + "-" * 65)
    print(f"[+] Administrator account '{username}' created successfully!")
    print(f"    Account ID   : {officer_id}")
    print(f"    Full Name    : {full_name}")
    print(f"    Role         : admin")
    print(f"    Status       : Active")
    print("-" * 65 + "\n")
    return officer_id


def main():
    parser = argparse.ArgumentParser(description="CSP_V2 Police System CLI Administration")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    admin_parser = subparsers.add_parser("create-admin", help="Create an Administrator account")
    admin_parser.add_argument("--username", help="Administrator username")
    admin_parser.add_argument("--full-name", help="Administrator full name")
    admin_parser.add_argument("--badge", help="Badge number / Police ID")
    admin_parser.add_argument("--password", help="Password (for non-interactive automation)")
    admin_parser.add_argument("--force", action="store_true", help="Bypass multi-admin confirmation prompt")
    admin_parser.add_argument("--db-path", help="Target SQLite database path (defaults to Config.DATABASE_PATH)")

    # Snapshot subcommand
    snapshot_parser = subparsers.add_parser("snapshot-db", help="Create a crash-consistent database snapshot")
    snapshot_parser.add_argument("--source", help="Source SQLite database path (defaults to Config.DATABASE_PATH)")
    snapshot_parser.add_argument("--target", required=True, help="Destination snapshot path")
    snapshot_parser.add_argument("--force", action="store_true", help="Overwrite target if it exists")

    # Verify subcommand
    verify_parser = subparsers.add_parser("verify-db", help="Perform read-only verification of a database")
    verify_parser.add_argument("--db-path", help="Target SQLite database path (defaults to Config.DATABASE_PATH)")
    verify_parser.add_argument("--expected-complaints", type=int, help="Expected complaints count")
    verify_parser.add_argument("--expected-officers", type=int, help="Expected officers count")
    verify_parser.add_argument("--expected-audit-logs", type=int, help="Expected minimum audit logs count")
    verify_parser.add_argument("--expected-sha256", help="Expected SHA-256 checksum")

    # Restore subcommand
    restore_parser = subparsers.add_parser("restore-db", help="Safely restore a validated database snapshot")
    restore_parser.add_argument("--source", required=True, help="Source backup snapshot path")
    restore_parser.add_argument("--target", help="Destination database path (defaults to Config.DATABASE_PATH)")
    restore_parser.add_argument("--force", action="store_true", help="Overwrite target if it exists")

    args = parser.parse_args()

    if args.command == "create-admin":
        res = create_admin_interactive(
            username=args.username,
            full_name=args.full_name,
            password=args.password,
            badge_number=args.badge,
            force=args.force,
            db_path=args.db_path
        )
        sys.exit(0 if res > 0 else 1)
    elif args.command == "snapshot-db":
        res = snapshot_database(
            source_path=args.source,
            target_path=args.target,
            force=args.force
        )
        sys.exit(0 if res == 0 else 1)
    elif args.command == "verify-db":
        res = verify_database(
            db_path=args.db_path,
            expected_complaints=args.expected_complaints,
            expected_officers=args.expected_officers,
            expected_audit_logs=args.expected_audit_logs,
            expected_sha256=args.expected_sha256
        )
        sys.exit(0 if res == 0 else 1)
    elif args.command == "restore-db":
        res = restore_database(
            source_path=args.source,
            target_path=args.target,
            force=args.force
        )
        sys.exit(0 if res == 0 else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

