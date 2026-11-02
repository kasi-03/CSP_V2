"""
Unit and integration tests for Officer Authentication and Security Audit Database schema and services.
Verifies idempotent migrations, role constraints, unique case-insensitive usernames,
officer lifecycle, audit logging, and preservation of complaint records.
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.services.database import (
    init_db,
    create_officer,
    get_officer_by_username,
    get_officer_by_id,
    list_officers,
    update_officer_status,
    record_login,
    create_audit_log,
    get_audit_logs,
    save_complaint,
    get_complaint_by_id,
    get_complaints,
    ALLOWED_ROLES
)


class TestOfficerDatabase(unittest.TestCase):

    def setUp(self):
        """Create an isolated temporary SQLite database for each test."""
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        # Initialize schema
        init_db(self.db_path)

    def tearDown(self):
        """Clean up temporary test database."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_01_officers_table_creation(self):
        """1. Verify officers table and its indexes are created correctly."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='officers'")
        self.assertIsNotNone(c.fetchone(), "officers table should exist")

        c.execute("PRAGMA table_info(officers)")
        cols = {row[1]: row[2] for row in c.fetchall()}
        expected_cols = [
            "id", "username", "password_hash", "full_name",
            "badge_number", "role", "is_active", "created_at",
            "updated_at", "last_login"
        ]
        for col in expected_cols:
            self.assertIn(col, cols, f"Column '{col}' must exist in officers table")

        # Verify indexes
        c.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='officers'")
        indexes = {row[0] for row in c.fetchall()}
        self.assertIn("idx_officers_username", indexes)
        self.assertIn("idx_officers_role", indexes)
        conn.close()

    def test_02_audit_logs_table_creation(self):
        """2. Verify audit_logs table and timestamp index are created correctly."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        self.assertIsNotNone(c.fetchone(), "audit_logs table should exist")

        c.execute("PRAGMA table_info(audit_logs)")
        cols = {row[1]: row[2] for row in c.fetchall()}
        expected_cols = [
            "id", "timestamp", "officer_id", "username",
            "ip_address", "action", "resource", "status", "details"
        ]
        for col in expected_cols:
            self.assertIn(col, cols, f"Column '{col}' must exist in audit_logs table")

        c.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_logs'")
        indexes = {row[0] for row in c.fetchall()}
        self.assertIn("idx_audit_logs_timestamp", indexes)
        conn.close()

    def test_03_duplicate_username_rejection(self):
        """3. Verify duplicate usernames, including case variations, are rejected."""
        create_officer(
            username="Officer_Alpha",
            password_hash="scrypt:32768:8:1$fakehash123",
            full_name="Test Officer Alpha",
            role="officer",
            db_path=self.db_path
        )

        # Exact duplicate
        with self.assertRaises(sqlite3.IntegrityError):
            create_officer(
                username="Officer_Alpha",
                password_hash="scrypt:32768:8:1$fakehash456",
                full_name="Test Officer Duplicate",
                role="officer",
                db_path=self.db_path
            )

        # Case-insensitive duplicate (COLLATE NOCASE)
        with self.assertRaises(sqlite3.IntegrityError):
            create_officer(
                username="OFFICER_ALPHA",
                password_hash="scrypt:32768:8:1$fakehash789",
                full_name="Test Officer Duplicate",
                role="officer",
                db_path=self.db_path
            )

        with self.assertRaises(sqlite3.IntegrityError):
            create_officer(
                username="officer_alpha",
                password_hash="scrypt:32768:8:1$fakehash000",
                full_name="Test Officer Duplicate",
                role="officer",
                db_path=self.db_path
            )

    def test_04_invalid_role_rejection(self):
        """4. Verify invalid role values are rejected at service and database level."""
        # Service level validation raises ValueError
        with self.assertRaises(ValueError):
            create_officer(
                username="test_bad_role",
                password_hash="scrypt:32768:8:1$fakehash123",
                full_name="Test Bad Role",
                role="superadmin",  # Invalid
                db_path=self.db_path
            )

        with self.assertRaises(ValueError):
            create_officer(
                username="test_empty_role",
                password_hash="scrypt:32768:8:1$fakehash123",
                full_name="Test Empty Role",
                role="",  # Invalid
                db_path=self.db_path
            )

        # Database CHECK constraint validation
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute(
                """
                INSERT INTO officers (username, password_hash, full_name, role, is_active, created_at, updated_at)
                VALUES ('raw_invalid', 'hash', 'Name', 'unauthorized_role', 1, '2026-01-01', '2026-01-01')
                """
            )
        conn.close()

    def test_05_officer_creation_and_retrieval(self):
        """5. Verify officer creation, structured retrieval, and password_hash safety."""
        officer_id = create_officer(
            username="investigator1",
            password_hash="scrypt:32768:8:1$securehash999",
            full_name="Test Officer Beta",
            role="officer",
            badge_number="AP-POL-4021",
            db_path=self.db_path
        )
        self.assertIsInstance(officer_id, int)
        self.assertGreater(officer_id, 0)

        # Retrieve by username (includes hash for auth verify)
        by_user = get_officer_by_username("investigator1", db_path=self.db_path)
        self.assertIsNotNone(by_user)
        self.assertEqual(by_user["id"], officer_id)
        self.assertEqual(by_user["username"], "investigator1")
        self.assertEqual(by_user["role"], "officer")
        self.assertEqual(by_user["badge_number"], "AP-POL-4021")
        self.assertTrue(by_user["is_active"])
        self.assertEqual(by_user["password_hash"], "scrypt:32768:8:1$securehash999")

        # Case-insensitive username lookup
        by_user_upper = get_officer_by_username("INVESTIGATOR1", db_path=self.db_path)
        self.assertIsNotNone(by_user_upper)
        self.assertEqual(by_user_upper["id"], officer_id)

        # Retrieve by ID (excludes password_hash by default)
        by_id_safe = get_officer_by_id(officer_id, include_hash=False, db_path=self.db_path)
        self.assertNotIn("password_hash", by_id_safe, "password_hash must NOT be in default get_officer_by_id")

        # Retrieve by ID with include_hash=True
        by_id_auth = get_officer_by_id(officer_id, include_hash=True, db_path=self.db_path)
        self.assertIn("password_hash", by_id_auth)

        # list_officers must NEVER expose password_hash
        all_officers = list_officers(db_path=self.db_path)
        self.assertEqual(len(all_officers), 1)
        self.assertNotIn("password_hash", all_officers[0])

    def test_06_officer_activation_and_deactivation(self):
        """6. Verify activating, deactivating officers and login recording."""
        officer_id = create_officer(
            username="desk_officer",
            password_hash="scrypt:32768:8:1$fakehash",
            full_name="Test Officer Gamma",
            role="officer",
            db_path=self.db_path
        )

        # Deactivate
        updated = update_officer_status(officer_id, is_active=False, db_path=self.db_path)
        self.assertTrue(updated)

        officer = get_officer_by_id(officer_id, db_path=self.db_path)
        self.assertFalse(officer["is_active"])

        # Check active-only filter
        active_list = list_officers(include_inactive=False, db_path=self.db_path)
        self.assertEqual(len(active_list), 0)

        all_list = list_officers(include_inactive=True, db_path=self.db_path)
        self.assertEqual(len(all_list), 1)

        # Reactivate
        updated = update_officer_status(officer_id, is_active=True, db_path=self.db_path)
        self.assertTrue(updated)
        officer_active = get_officer_by_id(officer_id, db_path=self.db_path)
        self.assertTrue(officer_active["is_active"])

        # Record login
        login_recorded = record_login(officer_id, login_time="2026-11-01 12:00:00", db_path=self.db_path)
        self.assertTrue(login_recorded)
        officer_logged = get_officer_by_id(officer_id, db_path=self.db_path)
        self.assertEqual(officer_logged["last_login"], "2026-11-01 12:00:00")

    def test_07_audit_log_creation(self):
        """7. Verify audit log creation, retrieval, and sensitive content redaction."""
        # Create officer first to satisfy foreign key constraint on officer_id
        officer_id = create_officer(
            username="admin_user",
            password_hash="hashed_pw_test",
            full_name="Admin User",
            role="admin",
            db_path=self.db_path
        )
        log_id = create_audit_log(
            officer_id=officer_id,
            username="admin_user",
            ip_address="127.0.0.1",
            action="OFFICER_STATUS_CHANGED",
            resource="officers/2",
            status="SUCCESS",
            details="Account deactivated",
            db_path=self.db_path
        )
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)

        logs = get_audit_logs(limit=10, db_path=self.db_path)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["action"], "OFFICER_STATUS_CHANGED")
        self.assertEqual(logs[0]["username"], "admin_user")
        self.assertEqual(logs[0]["status"], "SUCCESS")

        # Test automatic redaction of sensitive credentials in details
        log_id_redacted = create_audit_log(
            officer_id=officer_id,
            username="admin_user",
            ip_address="127.0.0.1",
            action="PASSWORD_ATTEMPT",
            resource="auth/login",
            status="FAILED",
            details="User entered password=SuperSecret123",
            db_path=self.db_path
        )
        logs = get_audit_logs(limit=10, db_path=self.db_path)
        self.assertEqual(logs[0]["details"], "[REDACTED_SENSITIVE_CONTENT]")

    def test_08_existing_complaint_records_remain_unchanged(self):
        """8. Verify existing complaint records remain unchanged before and after officer operations."""
        # Insert a sample complaint into the isolated test database
        cid = save_complaint(
            registered_on="01-11-2026 12:30 PM",
            english_name="Citizen Kumar",
            telugu_name="కుమార్",
            phone="9876543210",
            subject="Theft of Bicycle",
            audio_path="case_records/2026/November/C001/Complaint_Audio.wav",
            telugu_complaint="సైకిల్ దొంగతనం గురించి ఫిర్యాదు.",
            english_complaint="Complaint regarding bicycle theft.",
            db_path=self.db_path
        )

        complaint_before = get_complaint_by_id(cid, db_path=self.db_path)

        # Perform officer and audit operations
        oid = create_officer(
            username="audit_officer",
            password_hash="scrypt:hash",
            full_name="Audit Officer",
            role="viewer",
            db_path=self.db_path
        )
        create_audit_log(
            officer_id=oid,
            username="audit_officer",
            action="VIEW_COMPLAINT",
            resource=f"complaints/{cid}",
            status="SUCCESS",
            db_path=self.db_path
        )

        complaint_after = get_complaint_by_id(cid, db_path=self.db_path)
        self.assertEqual(complaint_before, complaint_after, "Complaint record must remain identical")

    def test_09_multiple_init_db_calls_idempotency(self):
        """9. Verify running init_db multiple times does not corrupt or duplicate data."""
        # Create an officer and a complaint
        oid = create_officer(
            username="steady_officer",
            password_hash="scrypt:hash",
            full_name="Steady Officer",
            role="admin",
            db_path=self.db_path
        )

        # Call init_db 3 more times
        for _ in range(3):
            init_db(self.db_path)

        # Verify officer still exists exactly as before
        officer = get_officer_by_id(oid, db_path=self.db_path)
        self.assertIsNotNone(officer)
        self.assertEqual(officer["username"], "steady_officer")

        # Verify total officers count is still exactly 1
        all_officers = list_officers(db_path=self.db_path)
        self.assertEqual(len(all_officers), 1)


if __name__ == "__main__":
    unittest.main()

