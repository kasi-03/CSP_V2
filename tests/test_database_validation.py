"""
tests/test_database_validation.py
=================================
Focused test suite for Phase 8.10: Safe Render SQLite Database Provisioning.

Verifies:
1. validate_production_database() fails fast on missing database file.
2. validate_production_database() fails fast on zero-byte database file.
3. validate_production_database() fails fast on corrupt database file.
4. validate_production_database() fails fast when required tables are missing.
5. validate_production_database() fails fast when no active administrator exists.
6. validate_production_database() fails fast on foreign key integrity violations.
7. validate_production_database() succeeds on a valid, populated production database.
8. Local development and unit-test databases remain unaffected when REQUIRE_EXISTING_DB is False.
9. Production environment with REQUIRE_EXISTING_DB=True strictly blocks startup on missing DB.
10. CLI snapshot-db creates crash-consistent backup via SQLite Backup API and preserves data.
11. CLI snapshot-db refuses to overwrite existing target file without --force.
12. CLI verify-db performs strictly read-only verification and validates schema and counts.
13. CLI restore-db pre-validates source, restores via atomic replacement, and refuses to overwrite target without --force.

100% Isolated: Uses temporary directories; strictly protects production complaints.db.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import (
    init_db,
    create_officer,
    save_complaint,
    validate_production_database,
    REQUIRED_DATABASE_TABLES
)
from backend.services.auth import hash_password
from backend.cli import (
    snapshot_database,
    verify_database,
    restore_database,
    compute_file_sha256
)


class TestDatabaseValidation(unittest.TestCase):
    """Test suite for production database pre-start validation and safe provisioning."""

    def setUp(self):
        """Create an isolated temporary environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="csp_test_db_val_")
        self.valid_db = os.path.join(self.temp_dir, "valid_prod.db")

        # Create a valid reference database
        init_db(self.valid_db)
        self.admin_id = create_officer(
            username="testadmin",
            password_hash=hash_password("SuperSecretAdminPass1!"),
            full_name="Test Administrator",
            role="admin",
            badge_number="POLICE-001",
            db_path=self.valid_db
        )
        self.complaint_id = save_complaint(
            registered_on="02-11-2026 12:00:00",
            english_name="Citizen John",
            telugu_name="జాన్",
            phone="9876543210",
            subject="Test Incident",
            audio_path="complaints/1/audio/Complaint_Audio.wav",
            telugu_complaint="ఫిర్యాదు",
            english_complaint="Complaint",
            db_path=self.valid_db
        )

    def tearDown(self):
        """Clean up temporary test artifacts."""
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except OSError:
                pass

    def test_01_missing_database_raises_error(self):
        """1. Verify validate_production_database fails on non-existent database file."""
        missing_db = os.path.join(self.temp_dir, "missing.db")
        self.assertFalse(os.path.exists(missing_db))

        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(missing_db)
        self.assertIn("does not exist", str(ctx.exception))
        self.assertIn("CRITICAL DEPLOYMENT SAFETY ERROR", str(ctx.exception))

    def test_02_zero_byte_database_raises_error(self):
        """2. Verify validate_production_database fails on 0-byte database file."""
        zero_db = os.path.join(self.temp_dir, "empty_zero.db")
        open(zero_db, "wb").close()
        self.assertEqual(os.path.getsize(zero_db), 0)

        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(zero_db)
        self.assertIn("empty (0 bytes)", str(ctx.exception))

    def test_03_corrupt_database_raises_error(self):
        """3. Verify validate_production_database fails on corrupted/malformed database file."""
        corrupt_db = os.path.join(self.temp_dir, "corrupt.db")
        with open(corrupt_db, "wb") as f:
            f.write(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_DATA_1234567890")

        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(corrupt_db)
        err = str(ctx.exception).lower()
        self.assertTrue(
            "integrity check failed" in err or
            "unable to open" in err or
            "not a database" in err or
            "validation query failed" in err
        )

    def test_04_missing_tables_raises_error(self):
        """4. Verify validate_production_database fails when required tables are missing."""
        incomplete_db = os.path.join(self.temp_dir, "incomplete.db")
        conn = sqlite3.connect(incomplete_db)
        conn.execute("CREATE TABLE dummy (id INTEGER PRIMARY KEY);")
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(incomplete_db)
        self.assertIn("missing required table", str(ctx.exception))

    def test_05_missing_active_admin_raises_error(self):
        """5. Verify validate_production_database fails when 0 active admin accounts exist."""
        no_admin_db = os.path.join(self.temp_dir, "no_admin.db")
        init_db(no_admin_db)

        # Deactivate or don't create admin (currently officers table is empty)
        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(no_admin_db)
        self.assertIn("0 active Administrator accounts", str(ctx.exception))

        # Add a viewer only
        create_officer(
            username="viewer_user",
            password_hash=hash_password("Pass12345!"),
            full_name="Viewer Officer",
            role="viewer",
            db_path=no_admin_db
        )
        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(no_admin_db)
        self.assertIn("0 active Administrator accounts", str(ctx.exception))

    def test_06_foreign_key_violation_raises_error(self):
        """6. Verify validate_production_database detects foreign key violations."""
        fk_db = os.path.join(self.temp_dir, "fk_violation.db")
        init_db(fk_db)
        create_officer(
            username="fk_admin",
            password_hash=hash_password("Pass12345!"),
            full_name="Admin",
            role="admin",
            db_path=fk_db
        )

        # Insert audit log with invalid officer_id while foreign keys are off
        conn = sqlite3.connect(fk_db)
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute(
            """
            INSERT INTO audit_logs (timestamp, officer_id, username, action, resource, status)
            VALUES ('2026-11-02 12:00:00', 99999, 'nonexistent', 'TEST', 'test', 'SUCCESS')
            """
        )
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            validate_production_database(fk_db)
        self.assertIn("foreign key violation", str(ctx.exception))

    def test_07_valid_production_database_succeeds(self):
        """7. Verify validate_production_database succeeds on a fully compliant database."""
        self.assertTrue(validate_production_database(self.valid_db))

    def test_08_local_dev_works_normally_when_require_existing_db_is_false(self):
        """8. Verify create_app() creates a fresh database when REQUIRE_EXISTING_DB=False."""
        fresh_db = os.path.join(self.temp_dir, "local_dev_new.db")
        self.assertFalse(os.path.exists(fresh_db))

        class LocalDevConfig(Config):
            TESTING = True
            WTF_CSRF_ENABLED = False
            DATABASE_PATH = fresh_db
            REQUIRE_EXISTING_DB = False
            SESSION_FILE_DIR = os.path.join(self.temp_dir, "sess_dev")

        app = create_app(config_class=LocalDevConfig)
        self.assertTrue(os.path.exists(fresh_db))

        # Health endpoint reports 200
        client = app.test_client()
        res = client.get("/health")
        self.assertEqual(res.status_code, 200)

    def test_09_production_mode_blocks_startup_when_require_existing_db_is_true(self):
        """9. Verify create_app() raises RuntimeError when REQUIRE_EXISTING_DB=True on missing DB."""
        missing_db = os.path.join(self.temp_dir, "production_missing.db")
        self.assertFalse(os.path.exists(missing_db))

        class ProdMissingConfig(Config):
            TESTING = True
            WTF_CSRF_ENABLED = False
            DATABASE_PATH = missing_db
            REQUIRE_EXISTING_DB = True
            SESSION_FILE_DIR = os.path.join(self.temp_dir, "sess_prod")

        with self.assertRaises(RuntimeError) as ctx:
            create_app(config_class=ProdMissingConfig)

        self.assertIn("does not exist", str(ctx.exception))
        self.assertFalse(os.path.exists(missing_db), "Missing database must NOT be created")

    def test_10_cli_snapshot_db_creates_consistent_backup(self):
        """10. Verify CLI snapshot-db command creates a faithful backup matching the source."""
        snapshot_dest = os.path.join(self.temp_dir, "snapshots", "backup_test.db")
        res = snapshot_database(
            source_path=self.valid_db,
            target_path=snapshot_dest,
            force=False
        )
        self.assertEqual(res, 0)
        self.assertTrue(os.path.exists(snapshot_dest))

        # Verify snapshot matches source content and passes full validation
        self.assertTrue(validate_production_database(snapshot_dest))

        from backend.services.database import get_complaint_by_id, get_officer_by_username
        src_comp = get_complaint_by_id(self.complaint_id, db_path=self.valid_db)
        snap_comp = get_complaint_by_id(self.complaint_id, db_path=snapshot_dest)
        self.assertEqual(src_comp, snap_comp)

        src_admin = get_officer_by_username("testadmin", db_path=self.valid_db)
        snap_admin = get_officer_by_username("testadmin", db_path=snapshot_dest)
        self.assertEqual(src_admin, snap_admin)

    def test_11_cli_snapshot_db_refuses_overwrite_without_force(self):
        """11. Verify CLI snapshot-db refuses to overwrite existing destination without --force."""
        snapshot_dest = os.path.join(self.temp_dir, "existing_snapshot.db")
        with open(snapshot_dest, "wb") as f:
            f.write(b"existing_content")

        res = snapshot_database(
            source_path=self.valid_db,
            target_path=snapshot_dest,
            force=False
        )
        self.assertEqual(res, -1)
        # Content remains untouched
        with open(snapshot_dest, "rb") as f:
            self.assertEqual(f.read(), b"existing_content")

        # Overwrite with force=True succeeds
        res_forced = snapshot_database(
            source_path=self.valid_db,
            target_path=snapshot_dest,
            force=True
        )
        self.assertEqual(res_forced, 0)
        self.assertTrue(validate_production_database(snapshot_dest))

    def test_12_cli_verify_db_checks(self):
        """12. Verify CLI verify-db returns 0 on matching expectations and -1 on mismatches."""
        sha = compute_file_sha256(self.valid_db)

        # Matching expectations
        res = verify_database(
            db_path=self.valid_db,
            expected_complaints=1,
            expected_officers=1,
            expected_sha256=sha
        )
        self.assertEqual(res, 0)

        # Mismatched expectations
        res_mismatch = verify_database(
            db_path=self.valid_db,
            expected_complaints=999
        )
        self.assertEqual(res_mismatch, -1)

    def test_13_cli_restore_db_safety_and_atomicity(self):
        """13. Verify CLI restore-db validates source, restores atomically, and refuses automatic overwrite."""
        # 1. Take a snapshot to restore from
        snapshot_src = os.path.join(self.temp_dir, "snapshot_src.db")
        snapshot_database(source_path=self.valid_db, target_path=snapshot_src, force=True)

        restore_dest = os.path.join(self.temp_dir, "restored_dir", "complaints_restored.db")
        self.assertFalse(os.path.exists(restore_dest))

        # Restore to new target
        res = restore_database(source_path=snapshot_src, target_path=restore_dest, force=False)
        self.assertEqual(res, 0)
        self.assertTrue(os.path.exists(restore_dest))
        self.assertTrue(validate_production_database(restore_dest))

        # Attempt to restore again without --force must be refused
        res_refused = restore_database(source_path=snapshot_src, target_path=restore_dest, force=False)
        self.assertEqual(res_refused, -1)

        # Attempt to restore from corrupt source must be refused
        bad_src = os.path.join(self.temp_dir, "bad_source.db")
        with open(bad_src, "wb") as f:
            f.write(b"garbage")
        res_bad = restore_database(source_path=bad_src, target_path=os.path.join(self.temp_dir, "never.db"), force=False)
        self.assertEqual(res_bad, -1)


if __name__ == "__main__":
    unittest.main()
