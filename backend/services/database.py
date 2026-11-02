import os
import sqlite3
from datetime import datetime, timedelta
from config import Config


ALLOWED_ROLES = {"admin", "officer", "viewer"}
REQUIRED_DATABASE_TABLES = {"complaints", "officers", "audit_logs", "login_attempts"}


def validate_production_database(db_path=None) -> bool:
    """
    Validate that a production database exists, is uncorrupted, and contains
    the required minimum schema and administrative account before allowing application startup.
    Fails fast to prevent accidental creation of an empty database on persistent storage (Phase 8.10).

    Safeguards:
    1. Rejects missing, non-existent, or 0-byte database files.
    2. Opens file strictly in read-only URI mode ('file:{path}?mode=ro').
    3. Runs 'PRAGMA integrity_check' and 'PRAGMA foreign_key_check'.
    4. Verifies all required tables exist.
    5. Verifies at least one active administrator account exists.
    6. Never modifies, creates, or deletes any files or records.
    7. Zero exposure of password hashes, credentials, or record contents in error messages.
    """
    path = db_path or Config.DATABASE_PATH
    if not path or path == ":memory:":
        return True

    clean_path = str(path)
    if clean_path.startswith("file:"):
        clean_path = clean_path.split("?")[0].replace("file:", "")

    abs_path = os.path.abspath(clean_path)

    if not os.path.exists(abs_path):
        raise RuntimeError(
            f"CRITICAL DEPLOYMENT SAFETY ERROR: Configured database file does not exist at '{abs_path}'. "
            f"Application startup aborted to prevent accidental creation of an empty database. "
            f"Restore or provision the production database before starting the application."
        )

    if not os.path.isfile(abs_path):
        raise RuntimeError(
            f"CRITICAL DEPLOYMENT SAFETY ERROR: Configured database path '{abs_path}' is not a regular file. "
            f"Application startup aborted."
        )

    if os.path.getsize(abs_path) == 0:
        raise RuntimeError(
            f"CRITICAL DEPLOYMENT SAFETY ERROR: Configured database file '{abs_path}' is empty (0 bytes). "
            f"Application startup aborted."
        )

    # Open strictly in read-only mode using SQLite URI
    uri = f"file:{abs_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        raise RuntimeError(
            f"CRITICAL DEPLOYMENT SAFETY ERROR: Unable to open database at '{abs_path}' in read-only mode: {e}"
        )

    try:
        try:
            cursor = conn.cursor()

            # 1. PRAGMA integrity_check
            cursor.execute("PRAGMA integrity_check")
            integrity_rows = cursor.fetchall()
            if not integrity_rows or integrity_rows[0][0] != "ok":
                details = [str(r[0]) for r in integrity_rows[:5]]
                raise RuntimeError(
                    f"CRITICAL DEPLOYMENT SAFETY ERROR: Database integrity check failed on '{abs_path}': {details}"
                )

            # 2. PRAGMA foreign_key_check
            cursor.execute("PRAGMA foreign_key_check")
            fk_violations = cursor.fetchall()
            if fk_violations:
                raise RuntimeError(
                    f"CRITICAL DEPLOYMENT SAFETY ERROR: Database has {len(fk_violations)} foreign key violation(s) on '{abs_path}'."
                )

            # 3. Verify required tables and schema
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in cursor.fetchall()}
            missing_tables = REQUIRED_DATABASE_TABLES - existing_tables
            if missing_tables:
                raise RuntimeError(
                    f"CRITICAL DEPLOYMENT SAFETY ERROR: Database at '{abs_path}' is missing required table(s): {', '.join(sorted(missing_tables))}."
                )

            # 4. Verify at least one active administrator exists
            cursor.execute("SELECT COUNT(*) FROM officers WHERE role = 'admin' AND is_active = 1")
            admin_count = cursor.fetchone()[0]
            if admin_count < 1:
                raise RuntimeError(
                    f"CRITICAL DEPLOYMENT SAFETY ERROR: Database at '{abs_path}' contains 0 active Administrator accounts. "
                    f"At least one active Administrator must exist before starting the application."
                )

            return True
        except sqlite3.Error as e:
            raise RuntimeError(
                f"CRITICAL DEPLOYMENT SAFETY ERROR: Database validation query failed on '{abs_path}': {e}"
            )
    finally:
        conn.close()


def get_connection(db_path=None):
    """
    Return an SQLite database connection with foreign key constraints enforced.

    SEC-08: SQLite foreign keys are disabled by default on every new connection.
    Executing 'PRAGMA foreign_keys = ON;' centrally here ensures all connection
    paths strictly enforce foreign key integrity before any transactions begin.
    """
    path = db_path or Config.DATABASE_PATH
    if path and path != ":memory:" and not str(path).startswith("file:"):
        db_dir = os.path.dirname(os.path.abspath(path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def check_db_health(db_path=None) -> bool:
    """
    Perform a lightweight read-only connectivity check against SQLite (SEC-07).
    Executes 'SELECT 1' to verify database availability and responsiveness.
    Guarantees connection cleanup and suppresses internal exceptions.
    Returns True if reachable and functional, False on any failure.
    """
    path = db_path or Config.DATABASE_PATH
    if path and path != ":memory:" and not str(path).startswith("file:"):
        if not os.path.exists(path):
            return False
    try:
        conn = get_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
            return row is not None and row[0] == 1
        finally:
            conn.close()
    except Exception:
        return False


def init_db(db_path=None):
    """
    Initialize the database schema if not already present, with idempotent migrations.
    Safely creates complaints, officers, and audit_logs tables and indexes.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        registered_on TEXT,
        english_name TEXT,
        telugu_name TEXT,
        phone TEXT,
        subject TEXT,
        audio_path TEXT,
        telugu_complaint TEXT,
        english_complaint TEXT
    )
    """)
    conn.commit()

    # Idempotent migration: add storage metadata columns if they do not exist
    cursor.execute("PRAGMA table_info(complaints)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    if "storage_backend" not in existing_columns:
        cursor.execute("ALTER TABLE complaints ADD COLUMN storage_backend TEXT DEFAULT 'local'")
    if "telugu_pdf_path" not in existing_columns:
        cursor.execute("ALTER TABLE complaints ADD COLUMN telugu_pdf_path TEXT")
    if "english_pdf_path" not in existing_columns:
        cursor.execute("ALTER TABLE complaints ADD COLUMN english_pdf_path TEXT")

    # Idempotent migration: create officers table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS officers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        badge_number TEXT,
        role TEXT NOT NULL CHECK(role IN ('admin', 'officer', 'viewer')),
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_login TEXT
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_officers_username ON officers(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_officers_role ON officers(role)")

    # Idempotent migration: create audit_logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        officer_id INTEGER,
        username TEXT,
        ip_address TEXT,
        action TEXT NOT NULL,
        resource TEXT,
        status TEXT NOT NULL,
        details TEXT,
        FOREIGN KEY(officer_id) REFERENCES officers(id)
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)")

    # Idempotent migration: create login_attempts table for lockout protection
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE,
        ip_address TEXT,
        attempted_at TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username, attempted_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at)")

    conn.commit()
    conn.close()



def save_complaint(
    registered_on,
    english_name,
    telugu_name,
    phone,
    subject,
    audio_path,
    telugu_complaint,
    english_complaint,
    db_path=None
):
    """Save a new complaint record and return its primary key ID."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO complaints(
                registered_on,
                english_name,
                telugu_name,
                phone,
                subject,
                audio_path,
                telugu_complaint,
                english_complaint
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                registered_on,
                english_name,
                telugu_name,
                phone,
                subject,
                audio_path,
                telugu_complaint,
                english_complaint
            )
        )
        complaint_id = cursor.lastrowid
        conn.commit()
        return complaint_id
    finally:
        conn.close()


def get_complaints(db_path=None):
    """Retrieve all complaints ordered by newest first."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM complaints
            ORDER BY id DESC
            """
        )
        rows = cursor.fetchall()
        return rows
    finally:
        conn.close()


def get_complaint_by_id(complaint_id, db_path=None):
    """Retrieve a single complaint record by its primary key ID."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM complaints
            WHERE id=?
            """,
            (complaint_id,)
        )
        row = cursor.fetchone()
        return row
    finally:
        conn.close()


def update_audio_path(complaint_id, audio_path, db_path=None):
    """Update the recorded audio destination path for a given complaint."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE complaints
        SET audio_path = ?
        WHERE id = ?
        """,
        (audio_path, complaint_id)
    )
    conn.commit()
    conn.close()


def update_complaint_storage(
    complaint_id: int,
    storage_backend: str,
    audio_path: str,
    telugu_pdf_path: str = None,
    english_pdf_path: str = None,
    db_path: str = None
):
    """Update the recorded storage backend and file paths / keys for a complaint."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE complaints
        SET storage_backend = ?,
            audio_path = ?,
            telugu_pdf_path = ?,
            english_pdf_path = ?
        WHERE id = ?
        """,
        (storage_backend, audio_path, telugu_pdf_path, english_pdf_path, complaint_id)
    )
    conn.commit()
    conn.close()


def get_complaint_storage_info(complaint_id: int, db_path: str = None):
    """Retrieve structured storage metadata for a complaint."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, storage_backend, audio_path, telugu_pdf_path, english_pdf_path
        FROM complaints
        WHERE id = ?
        """,
        (complaint_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "storage_backend": row[1] or "local",
        "audio_path": row[2],
        "telugu_pdf_path": row[3],
        "english_pdf_path": row[4]
    }



def get_statistics():
    """Compute overall, daily, and monthly complaint counts."""
    conn = get_connection()
    cursor = conn.cursor()

    # Total complaints
    cursor.execute("SELECT COUNT(*) FROM complaints")
    total_cases = cursor.fetchone()[0]

    # Today's complaints
    today = datetime.now().strftime("%d-%m-%Y")
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM complaints
        WHERE registered_on LIKE ?
        """,
        (f"{today}%",)
    )
    today_cases = cursor.fetchone()[0]

    # Current month's complaints
    current_month = datetime.now().strftime("%m-%Y")
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM complaints
        WHERE registered_on LIKE ?
        """,
        (f"%-{current_month}%",)
    )
    month_cases = cursor.fetchone()[0]

    conn.close()
    return total_cases, today_cases, month_cases


# =====================================================================
# Officer Management and Security Audit Services
# =====================================================================

def create_officer(
    username: str,
    password_hash: str,
    full_name: str,
    role: str,
    badge_number: str = None,
    db_path: str = None
) -> int:
    """
    Create a new officer account using parameterized SQL.
    Validates role, non-empty username, and presence of password hash.
    Enforces unique case-insensitive username.
    """
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    clean_username = username.strip()

    if not password_hash or not password_hash.strip():
        raise ValueError("Password hash is required.")

    if not full_name or not full_name.strip():
        raise ValueError("Full name cannot be empty.")
    clean_full_name = full_name.strip()

    clean_role = (role or "").strip().lower()
    if clean_role not in ALLOWED_ROLES:
        raise ValueError(
            f"Invalid role: '{role}'. Allowed roles are: {', '.join(sorted(ALLOWED_ROLES))}"
        )

    clean_badge = badge_number.strip() if badge_number and badge_number.strip() else None
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO officers (
                username,
                password_hash,
                full_name,
                badge_number,
                role,
                is_active,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                clean_username,
                password_hash.strip(),
                clean_full_name,
                clean_badge,
                clean_role,
                now,
                now
            )
        )
        officer_id = cursor.lastrowid
        conn.commit()
        return officer_id
    finally:
        conn.close()


def get_officer_by_username(username: str, db_path: str = None):
    """
    Retrieve an officer record by username.
    Includes password_hash strictly for authentication credential verification.
    Returns dict or None if not found.
    """
    if not username:
        return None

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, password_hash, full_name, badge_number, role, is_active, created_at, updated_at, last_login
        FROM officers
        WHERE username = ?
        """,
        (username.strip(),)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "full_name": row[3],
        "badge_number": row[4],
        "role": row[5],
        "is_active": bool(row[6]),
        "created_at": row[7],
        "updated_at": row[8],
        "last_login": row[9]
    }


def get_officer_by_id(officer_id: int, include_hash: bool = False, db_path: str = None):
    """
    Retrieve an officer record by primary key ID.
    By default, password_hash is excluded to prevent accidental exposure.
    Returns dict or None if not found.
    """
    if not officer_id:
        return None

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, password_hash, full_name, badge_number, role, is_active, created_at, updated_at, last_login
        FROM officers
        WHERE id = ?
        """,
        (officer_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    officer = {
        "id": row[0],
        "username": row[1],
        "full_name": row[3],
        "badge_number": row[4],
        "role": row[5],
        "is_active": bool(row[6]),
        "created_at": row[7],
        "updated_at": row[8],
        "last_login": row[9]
    }
    if include_hash:
        officer["password_hash"] = row[2]
    return officer


def list_officers(include_inactive: bool = True, db_path: str = None):
    """
    Retrieve all officer records ordered by ID ascending.
    SECURITY: password_hash is never exposed in listed records.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    if include_inactive:
        cursor.execute(
            """
            SELECT id, username, full_name, badge_number, role, is_active, created_at, updated_at, last_login
            FROM officers
            ORDER BY id ASC
            """
        )
    else:
        cursor.execute(
            """
            SELECT id, username, full_name, badge_number, role, is_active, created_at, updated_at, last_login
            FROM officers
            WHERE is_active = 1
            ORDER BY id ASC
            """
        )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "username": r[1],
            "full_name": r[2],
            "badge_number": r[3],
            "role": r[4],
            "is_active": bool(r[5]),
            "created_at": r[6],
            "updated_at": r[7],
            "last_login": r[8]
        }
        for r in rows
    ]


def update_officer_status_atomic(officer_id: int, is_active: bool, db_path: str = None) -> tuple[bool, str]:
    """
    Atomically activate or deactivate an officer account within a BEGIN IMMEDIATE transaction.
    Enforces that the last active Administrator cannot be deactivated, even under concurrent requests.
    Returns: (success: bool, error_message: str)
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection(db_path)
    try:
        conn.isolation_level = None
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute("SELECT role, is_active, username FROM officers WHERE id = ?", (officer_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("ROLLBACK")
            return False, "Officer account not found."

        role, current_status, username = (row[0] or "").lower(), bool(row[1]), row[2]

        # If deactivating an active administrator:
        if not is_active and role == "admin" and current_status:
            cursor.execute("SELECT COUNT(*) FROM officers WHERE role = 'admin' AND is_active = 1")
            active_admin_count = cursor.fetchone()[0]
            if active_admin_count <= 1:
                cursor.execute("ROLLBACK")
                return False, "Cannot modify account: At least one active Administrator must remain in the system."

        cursor.execute(
            """
            UPDATE officers
            SET is_active = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (1 if is_active else 0, now, officer_id)
        )
        cursor.execute("COMMIT")
        return True, ""
    except Exception as e:
        try:
            cursor.execute("ROLLBACK")
        except Exception:
            pass
        raise e
    finally:
        conn.close()


def update_officer_status(officer_id: int, is_active: bool, db_path: str = None) -> bool:
    """
    Activate or deactivate an officer account.
    Returns True if an officer record was updated.
    """
    success, _ = update_officer_status_atomic(officer_id, is_active, db_path=db_path)
    return success


def record_login(officer_id: int, login_time: str = None, db_path: str = None) -> bool:
    """
    Update last_login and updated_at timestamps upon successful officer authentication.
    Returns True if an officer record was updated.
    """
    now = login_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE officers
            SET last_login = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (now, now, officer_id)
        )
        updated = cursor.rowcount > 0
        conn.commit()
        return updated
    finally:
        conn.close()


def create_audit_log(
    officer_id: int = None,
    username: str = None,
    ip_address: str = None,
    action: str = None,
    resource: str = None,
    status: str = "SUCCESS",
    details: str = None,
    db_path: str = None
) -> int:
    """
    Create an immutable audit log entry using parameterized SQL.
    Scrubs obvious sensitive credential keywords from details to prevent accidental leaks.
    """
    if not action:
        raise ValueError("Audit log action is required.")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    clean_details = details
    if clean_details and any(k in clean_details.lower() for k in ("password", "token", "secret", "bearer")):
        clean_details = "[REDACTED_SENSITIVE_CONTENT]"

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (
                timestamp,
                officer_id,
                username,
                ip_address,
                action,
                resource,
                status,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                officer_id,
                username,
                ip_address,
                action,
                resource,
                status,
                clean_details
            )
        )
        log_id = cursor.lastrowid
        conn.commit()
        return log_id
    finally:
        conn.close()


def get_audit_logs(limit: int = 100, db_path: str = None):
    """
    Retrieve recent audit logs ordered by timestamp descending.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, officer_id, username, ip_address, action, resource, status, details
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "officer_id": r[2],
            "username": r[3],
            "ip_address": r[4],
            "action": r[5],
            "resource": r[6],
            "status": r[7],
            "details": r[8]
        }
        for r in rows
    ]


def get_officers_count(role: str = None, db_path: str = None) -> int:
    """
    Return the total number of officer accounts, optionally filtered by role.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    if role:
        cursor.execute("SELECT COUNT(*) FROM officers WHERE role = ?", (role.strip().lower(),))
    else:
        cursor.execute("SELECT COUNT(*) FROM officers")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def record_login_attempt(
    username: str,
    ip_address: str = None,
    success: bool = False,
    attempted_at: str = None,
    db_path: str = None
) -> int:
    """
    Record a login attempt (successful or failed) in SQLite for lockout analysis.
    """
    now = attempted_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_user = (username or "").strip()
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO login_attempts (username, ip_address, attempted_at, success)
            VALUES (?, ?, ?, ?)
            """,
            (clean_user, ip_address, now, 1 if success else 0)
        )
        attempt_id = cursor.lastrowid
        conn.commit()
        return attempt_id
    finally:
        conn.close()


def get_failed_login_attempts_count(
    username: str = None,
    ip_address: str = None,
    window_minutes: int = 15,
    db_path: str = None
) -> int:
    """
    Count consecutive failed login attempts within the given sliding time window
    since the last successful login.
    If username is provided, counts failed attempts for that user.
    If only ip_address is provided and verified, counts failed attempts for that IP.
    Unknown or internal proxy IPs are never counted globally to prevent proxy-wide lockouts.
    """
    from backend.services.proxy_service import is_verified_client_ip

    clean_user = (username or "").strip()
    cutoff = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if clean_user:
            cursor.execute(
                """
                SELECT MAX(attempted_at)
                FROM login_attempts
                WHERE username = ? AND success = 1 AND attempted_at >= ?
                """,
                (clean_user, cutoff)
            )
            last_success = cursor.fetchone()[0]
            if last_success:
                cutoff = last_success

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM login_attempts
                WHERE username = ?
                  AND success = 0
                  AND attempted_at >= ?
                """,
                (clean_user, cutoff)
            )
            return cursor.fetchone()[0]
        elif ip_address and is_verified_client_ip(ip_address):
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM login_attempts
                WHERE ip_address = ?
                  AND success = 0
                  AND attempted_at >= ?
                """,
                (ip_address.strip(), cutoff)
            )
            return cursor.fetchone()[0]

        return 0
    finally:
        conn.close()


def is_login_locked(
    username: str,
    ip_address: str = None,
    max_attempts: int = 5,
    window_minutes: int = 15,
    db_path: str = None
) -> tuple[bool, int]:
    """
    Determine whether a login attempt is currently locked out.
    Returns (is_locked: bool, remaining_lockout_minutes: int).

    Lockout Policy (SEC-02 Fail-Safe):
    1. Username-based lockout:
       - Checks consecutive failed attempts for clean_user within window_minutes.
       - If failed attempts >= max_attempts, the account is locked.
       - Protects against brute-force attacks on specific accounts across any IPs.
    2. IP-based lockout:
       - Applied ONLY when a verified public client IP is available (is_verified_client_ip is True).
       - If a verified public client IP has >= max_attempts failed attempts within window_minutes,
         attempts from that IP are blocked.
       - Protects against distributed credential stuffing / spraying from a single malicious host.
       - CRITICAL DEFENSE: If ip_address is None, empty, "unknown", loopback, private,
         or a shared reverse proxy socket IP, IP-based lockout is SKIPPED.
         This prevents shared internal proxy IPs from causing proxy-wide lockouts of unrelated users.
    """
    from backend.services.proxy_service import is_verified_client_ip

    clean_user = (username or "").strip()
    cutoff_dt = datetime.now() - timedelta(minutes=window_minutes)
    cutoff = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Username-based lockout check
        if clean_user:
            cursor.execute(
                """
                SELECT attempted_at
                FROM login_attempts
                WHERE username = ?
                  AND success = 0
                  AND attempted_at >= ?
                ORDER BY attempted_at DESC
                LIMIT ?
                """,
                (clean_user, cutoff, max_attempts)
            )
            user_rows = cursor.fetchall()
            if len(user_rows) >= max_attempts:
                most_recent_str = user_rows[0][0]
                try:
                    most_recent_dt = datetime.strptime(most_recent_str, "%Y-%m-%d %H:%M:%S")
                    elapsed = (datetime.now() - most_recent_dt).total_seconds()
                    remaining_seconds = max(0, (window_minutes * 60) - elapsed)
                    remaining_mins = int((remaining_seconds + 59) // 60)
                    return True, remaining_mins
                except Exception:
                    return True, window_minutes

        # 2. IP-based lockout check (applied ONLY if a verified public client IP is present)
        if ip_address and is_verified_client_ip(ip_address):
            cursor.execute(
                """
                SELECT attempted_at
                FROM login_attempts
                WHERE ip_address = ?
                  AND success = 0
                  AND attempted_at >= ?
                ORDER BY attempted_at DESC
                LIMIT ?
                """,
                (ip_address.strip(), cutoff, max_attempts)
            )
            ip_rows = cursor.fetchall()
            if len(ip_rows) >= max_attempts:
                most_recent_str = ip_rows[0][0]
                try:
                    most_recent_dt = datetime.strptime(most_recent_str, "%Y-%m-%d %H:%M:%S")
                    elapsed = (datetime.now() - most_recent_dt).total_seconds()
                    remaining_seconds = max(0, (window_minutes * 60) - elapsed)
                    remaining_mins = int((remaining_seconds + 59) // 60)
                    return True, remaining_mins
                except Exception:
                    return True, window_minutes

        return False, 0
    finally:
        conn.close()


def clear_failed_login_attempts(username: str, db_path: str = None):
    """
    Clear failed login attempt history for a username upon successful authentication.
    """
    clean_user = (username or "").strip()
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM login_attempts WHERE username = ?",
            (clean_user,)
        )
        conn.commit()
    finally:
        conn.close()


def update_officer_role_atomic(officer_id: int, new_role: str, db_path: str = None) -> tuple[bool, str]:
    """
    Atomically update an officer's role within a BEGIN IMMEDIATE transaction.
    Enforces that the last active Administrator cannot be demoted, even under concurrent requests.
    Returns: (success: bool, error_message: str)
    """
    clean_role = (new_role or "").strip().lower()
    if clean_role not in ALLOWED_ROLES:
        return False, f"Invalid role: '{new_role}'. Allowed roles are: {', '.join(sorted(ALLOWED_ROLES))}"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection(db_path)
    try:
        conn.isolation_level = None
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute("SELECT role, is_active, username FROM officers WHERE id = ?", (officer_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("ROLLBACK")
            return False, "Officer account not found."

        old_role, current_status, username = (row[0] or "").lower(), bool(row[1]), row[2]

        # If demoting an active administrator:
        if old_role == "admin" and clean_role != "admin" and current_status:
            cursor.execute("SELECT COUNT(*) FROM officers WHERE role = 'admin' AND is_active = 1")
            active_admin_count = cursor.fetchone()[0]
            if active_admin_count <= 1:
                cursor.execute("ROLLBACK")
                return False, "Cannot modify account: At least one active Administrator must remain in the system."

        cursor.execute(
            """
            UPDATE officers
            SET role = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (clean_role, now, officer_id)
        )
        cursor.execute("COMMIT")
        return True, ""
    except Exception as e:
        try:
            cursor.execute("ROLLBACK")
        except Exception:
            pass
        raise e
    finally:
        conn.close()


def update_officer_role(officer_id: int, new_role: str, db_path: str = None) -> bool:
    """
    Update the role of an officer. Enforces role constraint within ALLOWED_ROLES.
    Returns True if an officer record was updated.
    """
    success, reason = update_officer_role_atomic(officer_id, new_role, db_path=db_path)
    if not success and "Invalid role" in reason:
        raise ValueError(reason)
    return success


def update_officer_password(officer_id: int, new_password_hash: str, db_path: str = None) -> bool:
    """
    Update the password hash of an officer account.
    Returns True if an officer record was updated.
    """
    if not new_password_hash or not new_password_hash.strip():
        raise ValueError("Password hash cannot be empty.")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE officers
            SET password_hash = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (new_password_hash.strip(), now, officer_id)
        )
        updated = cursor.rowcount > 0
        conn.commit()
        return updated
    finally:
        conn.close()


def count_active_admins(db_path: str = None) -> int:
    """
    Return the total number of active administrator accounts.
    Critical safety check to prevent accidental demotion or deactivation of the last active Admin.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM officers
            WHERE role = 'admin' AND is_active = 1
            """
        )
        return cursor.fetchone()[0]
    finally:
        conn.close()


def get_audit_logs_paginated(
    page: int = 1,
    per_page: int = 25,
    action_filter: str = None,
    username_filter: str = None,
    db_path: str = None
) -> dict:
    """
    Retrieve audit logs with server-side pagination and optional filters.
    Returns: {
        'logs': list of dicts,
        'total': total records count,
        'page': current page,
        'per_page': per_page count,
        'total_pages': calculated total pages
    }
    """
    page = max(1, page)
    per_page = max(5, min(100, per_page))
    offset = (page - 1) * per_page

    where_clauses = []
    params = []

    if action_filter and action_filter.strip():
        where_clauses.append("action = ?")
        params.append(action_filter.strip())

    if username_filter and username_filter.strip():
        where_clauses.append("username LIKE ?")
        params.append(f"%{username_filter.strip()}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # Count total matching records
        cursor.execute(f"SELECT COUNT(*) FROM audit_logs {where_sql}", params)
        total = cursor.fetchone()[0]

        # Fetch page slice
        query = f"""
            SELECT id, timestamp, officer_id, username, ip_address, action, resource, status, details
            FROM audit_logs
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, params + [per_page, offset])
        rows = cursor.fetchall()

        logs = [
            {
                "id": r[0],
                "timestamp": r[1],
                "officer_id": r[2],
                "username": r[3],
                "ip_address": r[4],
                "action": r[5],
                "resource": r[6],
                "status": r[7],
                "details": r[8]
            }
            for r in rows
        ]

        total_pages = max(1, (total + per_page - 1) // per_page)

        return {
            "logs": logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages
        }
    finally:
        conn.close()



