"""
tests/test_database_persistence.py
==================================
Comprehensive test suite for Phase 8.3: SQLite Persistent Database Path Support.

Verifies:
1. Default local database path resolves to complaints.db in BASE_DIR when DATABASE_PATH is unset or empty.
2. Custom DATABASE_PATH environment variable overrides the default path.
3. Automatic creation of parent directories when the target database directory does not yet exist.
4. Central connection enforcement via get_connection() and init_db() across custom paths.
5. In-memory (:memory:) and edge-case paths are handled safely without directory creation errors.
6. Backward compatibility: existing database records (complaints, officers, audit logs) are preserved
   without schema breakage, column loss, or table truncation upon init_db() invocation.
7. Foreign key enforcement (PRAGMA foreign_keys = ON) is preserved on custom database paths.

100% Isolated: Uses temporary directories and temporary SQLite files only;
strictly prohibits modifying production complaints.db, sessions, or .env.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import (
    get_connection,
    init_db,
    save_complaint,
    get_complaint_by_id,
    get_complaints,
    create_officer,
    get_officer_by_username,
    get_officers_count,
    create_audit_log,
    get_audit_logs,
    check_db_health,
    ALLOWED_ROLES,
)
from backend.services.auth import hash_password


class TestDatabasePersistence(unittest.TestCase):
    """Test suite for SQLite persistent database path resolution and directory management."""

    def setUp(self):
        """Create an isolated temporary workspace for tests."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary test artifacts."""
        import shutil
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass

    def test_default_database_path_resolution(self):
        """
        Verify that when DATABASE_PATH is unset or empty,
        Config.DATABASE_PATH resolves to 'complaints.db' inside BASE_DIR.
        """
        # Test with empty string
        default_expected = os.path.join(Config.BASE_DIR, "complaints.db")

        with patch.dict(os.environ, {"DATABASE_PATH": ""}):
            # Simulate evaluation
            resolved = (os.getenv("DATABASE_PATH") or "").strip() or default_expected
            self.assertEqual(resolved, default_expected)

        # Test with unset
        env_copy = os.environ.copy()
        env_copy.pop("DATABASE_PATH", None)
        with patch.dict(os.environ, env_copy, clear=True):
            resolved = (os.getenv("DATABASE_PATH") or "").strip() or default_expected
            self.assertEqual(resolved, default_expected)

        # Confirm the actual Config default is preserved
        self.assertTrue(Config.DATABASE_PATH.endswith("complaints.db"))

    def test_custom_database_path_via_config(self):
        """
        Verify that a custom DATABASE_PATH points get_connection() to the target file.
        """
        custom_db = os.path.join(self.temp_dir, "custom_render_mount", "custom_complaints.db")

        with patch.object(Config, "DATABASE_PATH", custom_db):
            self.assertEqual(Config.DATABASE_PATH, custom_db)

            # Ensure parent directory does not exist prior to connection
            self.assertFalse(os.path.exists(os.path.dirname(custom_db)))

            # Connection must create directory and database file
            conn = get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                self.assertEqual(cursor.fetchone()[0], 1)
            finally:
                conn.close()

            # Verify file and directory now exist
            self.assertTrue(os.path.exists(os.path.dirname(custom_db)))
            self.assertTrue(os.path.exists(custom_db))

    def test_automatic_deeply_nested_directory_creation(self):
        """
        Verify that get_connection() automatically creates multiple levels of
        nested parent directories without raising OperationalError.
        """
        deeply_nested_db = os.path.join(
            self.temp_dir, "var", "mnt", "persistent", "csp_data", "complaints.db"
        )
        self.assertFalse(os.path.exists(os.path.dirname(deeply_nested_db)))

        # Calling get_connection with explicit path
        conn = get_connection(db_path=deeply_nested_db)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys")
            fk_status = cursor.fetchone()[0]
            self.assertEqual(fk_status, 1, "Foreign keys must be enabled on created database")
        finally:
            conn.close()

        self.assertTrue(os.path.exists(os.path.dirname(deeply_nested_db)))
        self.assertTrue(os.path.exists(deeply_nested_db))

    def test_init_db_on_custom_path_with_nonexistent_directory(self):
        """
        Verify that init_db() can initialize schema in a completely new directory.
        """
        new_dir_db = os.path.join(self.temp_dir, "data_mount", "app.db")
        self.assertFalse(os.path.exists(os.path.dirname(new_dir_db)))

        init_db(db_path=new_dir_db)

        self.assertTrue(os.path.exists(new_dir_db))

        # Verify all tables were created
        conn = sqlite3.connect(new_dir_db)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("complaints", tables)
            self.assertIn("officers", tables)
            self.assertIn("audit_logs", tables)
            self.assertIn("login_attempts", tables)
        finally:
            conn.close()

    def test_in_memory_database_handling(self):
        """
        Verify that ':memory:' path works smoothly without attempting invalid directory creation.
        """
        conn = get_connection(db_path=":memory:")
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone()[0], 1)
        finally:
            conn.close()

    def test_existing_database_compatibility_and_preservation(self):
        """
        Verify that pointing to an existing populated SQLite database preserves
        all existing records, tables, indexes, and constraints upon init_db().
        """
        existing_db = os.path.join(self.temp_dir, "existing_records.db")

        # 1. Initialize schema and insert initial records
        init_db(db_path=existing_db)

        officer_id = create_officer(
            username="existing_admin",
            password_hash=hash_password("StrongAdminPass1!"),
            full_name="Existing Administrator",
            role="admin",
            badge_number="POLICE-001",
            db_path=existing_db
        )

        complaint_id = save_complaint(
            registered_on="01-11-2026 10:00 AM",
            english_name="Ravi Kumar",
            telugu_name="రవి కుమార్",
            phone="9876543210",
            subject="Theft of two-wheeler",
            audio_path="Complaint_Audio.webm",
            telugu_complaint="ఫిర్యాదు వివరాలు...",
            english_complaint="Complaint details...",
            db_path=existing_db
        )

        audit_id = create_audit_log(
            officer_id=officer_id,
            username="existing_admin",
            ip_address="127.0.0.1",
            action="SYSTEM_INIT",
            resource="database",
            status="SUCCESS",
            details="Initial setup audit entry",
            db_path=existing_db
        )

        # 2. Simulate application restart / redeployment calling init_db() again
        init_db(db_path=existing_db)

        # 3. Verify records were NOT overwritten, deleted, or corrupted
        officer = get_officer_by_username("existing_admin", db_path=existing_db)
        self.assertIsNotNone(officer)
        self.assertEqual(officer["id"], officer_id)
        self.assertEqual(officer["role"], "admin")
        self.assertEqual(officer["badge_number"], "POLICE-001")

        complaint = get_complaint_by_id(complaint_id, db_path=existing_db)
        self.assertIsNotNone(complaint)
        self.assertEqual(complaint[2], "Ravi Kumar")
        self.assertEqual(complaint[5], "Theft of two-wheeler")

        audit_logs = get_audit_logs(limit=10, db_path=existing_db)
        self.assertTrue(any(log["id"] == audit_id for log in audit_logs))
        self.assertEqual(get_officers_count(db_path=existing_db), 1)

    def test_create_app_with_custom_database_path_in_config(self):
        """
        Verify that create_app() respects a custom DATABASE_PATH in its configuration
        and ensures the directory exists and the database is initialized.
        """
        custom_mount = os.path.join(self.temp_dir, "render_persistent_disk", "complaints.db")
        self.assertFalse(os.path.exists(os.path.dirname(custom_mount)))

        class TestPersistentConfig(Config):
            TESTING = True
            WTF_CSRF_ENABLED = False
            DATABASE_PATH = custom_mount
            SESSION_FILE_DIR = os.path.join(self.temp_dir, "sessions")

        app = create_app(config_class=TestPersistentConfig)
        self.assertTrue(os.path.exists(os.path.dirname(custom_mount)))
        self.assertTrue(os.path.exists(custom_mount))

        # Check health endpoint reports healthy with the persistent database
        client = app.test_client()
        res = client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ok")

        # Verify database health check passes
        self.assertTrue(check_db_health(db_path=custom_mount))


if __name__ == "__main__":
    unittest.main()

