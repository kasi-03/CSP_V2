"""
tests/test_foreign_keys.py
==========================
Comprehensive test suite for Phase 6.2.7 - SEC-08: SQLite Foreign Key Integrity.

Verifies:
1. Foreign key constraint enforcement (PRAGMA foreign_keys) is enabled on every new connection.
2. Invalid foreign-key references are strictly rejected (sqlite3.IntegrityError).
3. Valid related records can still be inserted successfully.
4. Foreign-key constraints prevent deletion of referenced parent records with active child records.
5. Foreign-key enforcement remains active across separate, independent connections.
6. Custom schema foreign keys behave with full relational integrity.
7. Transaction handling, atomic BEGIN IMMEDIATE, COMMIT, and ROLLBACK are preserved.
8. Existing database operations (complaints, login attempts, statistics) continue functioning.
"""

import os
import sqlite3
import tempfile
import unittest
from backend.services.database import (
    get_connection,
    init_db,
    create_officer,
    get_officer_by_id,
    create_audit_log,
    get_audit_logs,
    update_officer_status_atomic,
    update_officer_role_atomic,
    save_complaint,
    get_complaint_by_id,
    get_complaints,
    update_audio_path,
    update_complaint_storage,
    get_complaint_storage_info,
    get_statistics,
    record_login_attempt,
    is_login_locked,
    clear_failed_login_attempts,
)


class TestForeignKeyIntegrity(unittest.TestCase):
    """Focused test suite for SQLite foreign key constraint enforcement."""

    def setUp(self):
        """Create an isolated temporary database for each test to protect production data."""
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        # Initialize schema in temporary database
        init_db(self.db_path)

    def tearDown(self):
        """Clean up the isolated temporary database."""
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_01_foreign_keys_pragma_enabled_on_new_connection(self):
        """1. Verify PRAGMA foreign_keys returns 1 on every new connection from get_connection."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys;")
            result = cursor.fetchone()
            self.assertIsNotNone(result, "PRAGMA foreign_keys must return a result")
            self.assertEqual(
                result[0],
                1,
                f"PRAGMA foreign_keys must be 1 (enabled), but got {result[0]}"
            )
        finally:
            conn.close()

    def test_02_invalid_foreign_key_reference_rejected(self):
        """2. Verify inserting a record with an invalid foreign key reference is rejected."""
        # The officers table is currently empty in this temporary database.
        # Attempting to insert an audit_log with officer_id = 99999 must raise sqlite3.IntegrityError.
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            create_audit_log(
                officer_id=99999,
                username="nonexistent_officer",
                ip_address="127.0.0.1",
                action="INVALID_FK_TEST",
                status="FAILED",
                details="Testing foreign key rejection",
                db_path=self.db_path
            )
        self.assertIn("FOREIGN KEY constraint failed", str(ctx.exception))

        # Also verify raw SQL insert rejection through get_connection
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    """
                    INSERT INTO audit_logs (timestamp, officer_id, action, status)
                    VALUES ('2026-11-02 12:00:00', 88888, 'DIRECT_SQL_FK_TEST', 'FAILED')
                    """
                )
                conn.commit()
        finally:
            conn.close()

    def test_03_valid_related_records_inserted_successfully(self):
        """3. Verify valid related records and nullable foreign keys can still be inserted."""
        # Create a valid parent officer record
        officer_id = create_officer(
            username="valid_officer",
            password_hash="pbkdf2:sha256:valid_hash",
            full_name="Valid Officer",
            role="officer",
            db_path=self.db_path
        )
        self.assertIsInstance(officer_id, int)
        self.assertGreater(officer_id, 0)

        # Insert a valid child audit log referencing the existing officer
        log_id = create_audit_log(
            officer_id=officer_id,
            username="valid_officer",
            ip_address="192.168.1.100",
            action="OFFICER_LOGIN",
            status="SUCCESS",
            details="Successful login event",
            db_path=self.db_path
        )
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)

        # Verify nullable foreign key (officer_id is None / NULL for anonymous or unauthenticated events)
        null_log_id = create_audit_log(
            officer_id=None,
            username="anonymous",
            ip_address="192.168.1.200",
            action="UNAUTHENTICATED_ACCESS",
            status="WARNING",
            details="Access without authenticated session",
            db_path=self.db_path
        )
        self.assertIsInstance(null_log_id, int)
        self.assertGreater(null_log_id, 0)

        # Verify both logs exist
        logs = get_audit_logs(limit=10, db_path=self.db_path)
        self.assertEqual(len(logs), 2)

    def test_04_parent_deletion_rejected_when_child_references_exist(self):
        """4. Verify deleting a parent record is rejected when active child foreign key references exist."""
        # Create parent officer
        officer_id = create_officer(
            username="parent_officer",
            password_hash="pbkdf2:sha256:parent_hash",
            full_name="Parent Officer",
            role="officer",
            db_path=self.db_path
        )

        # Create child audit log referencing parent officer
        create_audit_log(
            officer_id=officer_id,
            username="parent_officer",
            action="AUDIT_ACTION",
            status="SUCCESS",
            db_path=self.db_path
        )

        # Attempt to delete the parent officer - foreign key constraint must reject deletion
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                cursor.execute("DELETE FROM officers WHERE id = ?", (officer_id,))
                conn.commit()
            self.assertIn("FOREIGN KEY constraint failed", str(ctx.exception))
        finally:
            conn.close()

    def test_05_foreign_key_enforcement_persists_across_separate_connections(self):
        """5. Verify foreign-key enforcement is enabled across multiple independent connections."""
        # Open and test connection 1
        conn1 = get_connection(self.db_path)
        try:
            fk1 = conn1.execute("PRAGMA foreign_keys;").fetchone()[0]
            self.assertEqual(fk1, 1, "Connection 1 must have foreign keys enabled")
        finally:
            conn1.close()

        # Open and test connection 2
        conn2 = get_connection(self.db_path)
        try:
            fk2 = conn2.execute("PRAGMA foreign_keys;").fetchone()[0]
            self.assertEqual(fk2, 1, "Connection 2 must have foreign keys enabled")

            # Verify constraint is actually enforced on connection 2
            with self.assertRaises(sqlite3.IntegrityError):
                conn2.execute(
                    "INSERT INTO audit_logs (timestamp, officer_id, action, status) VALUES (?, ?, ?, ?)",
                    ("2026-11-02 12:00:00", 77777, "CONN2_FK_TEST", "FAILED")
                )
                conn2.commit()
        finally:
            conn2.close()

        # Open and test connection 3
        conn3 = get_connection(self.db_path)
        try:
            fk3 = conn3.execute("PRAGMA foreign_keys;").fetchone()[0]
            self.assertEqual(fk3, 1, "Connection 3 must have foreign keys enabled")
        finally:
            conn3.close()

    def test_06_custom_schema_foreign_key_verification(self):
        """6. Verify custom parent-child tables respect foreign key integrity."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE test_departments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE test_employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    dept_id INTEGER NOT NULL,
                    FOREIGN KEY(dept_id) REFERENCES test_departments(id)
                )
            """)
            conn.commit()

            cursor.execute("INSERT INTO test_departments (name) VALUES ('Cybercrime')")
            dept_id = cursor.lastrowid
            conn.commit()

            # Valid insertion
            cursor.execute("INSERT INTO test_employees (name, dept_id) VALUES ('Alice', ?)", (dept_id,))
            conn.commit()

            # Invalid insertion (dept_id 999 does not exist)
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                cursor.execute("INSERT INTO test_employees (name, dept_id) VALUES ('Bob', 999)")
                conn.commit()
            self.assertIn("FOREIGN KEY constraint failed", str(ctx.exception))
        finally:
            conn.close()

    def test_07_transaction_handling_and_rollback_preserved(self):
        """7. Verify atomic transactions, BEGIN IMMEDIATE, COMMIT, and ROLLBACK remain functional."""
        # Create two admins
        admin1 = create_officer(
            username="admin1",
            password_hash="hash1",
            full_name="Admin One",
            role="admin",
            db_path=self.db_path
        )
        admin2 = create_officer(
            username="admin2",
            password_hash="hash2",
            full_name="Admin Two",
            role="admin",
            db_path=self.db_path
        )

        # Demote admin1 successfully (admin2 remains active)
        success, msg = update_officer_role_atomic(admin1, "officer", db_path=self.db_path)
        self.assertTrue(success)
        self.assertEqual(msg, "")

        # Attempt to demote admin2 (the last active admin) - must fail and rollback
        success2, msg2 = update_officer_role_atomic(admin2, "officer", db_path=self.db_path)
        self.assertFalse(success2)
        self.assertIn("At least one active Administrator must remain", msg2)

        # Verify admin2's role was rolled back and is still admin
        admin2_record = get_officer_by_id(admin2, db_path=self.db_path)
        self.assertEqual(admin2_record["role"], "admin")

        # Test manual explicit transaction rollback with foreign keys enabled
        conn = get_connection(self.db_path)
        try:
            conn.isolation_level = None
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "INSERT INTO complaints (registered_on, english_name, subject) VALUES (?, ?, ?)",
                ("02-11-2026", "Test Person", "Test Subject")
            )
            cursor.execute("ROLLBACK")

            # Verify record was rolled back
            cursor.execute("SELECT COUNT(*) FROM complaints WHERE english_name = 'Test Person'")
            self.assertEqual(cursor.fetchone()[0], 0)
        finally:
            conn.close()

    def test_08_existing_database_operations_continue_working(self):
        """8. Verify complaints, storage metadata, login attempts, and statistics operations work."""
        # 1. Save complaint
        cid = save_complaint(
            registered_on="02-11-2026 10:00 AM",
            english_name="John Doe",
            telugu_name="జాన్ డో",
            phone="9876543210",
            subject="Noise Complaint",
            audio_path="case_records/2026/November/C001/audio.wav",
            telugu_complaint="శబ్ద కాలుష్యం ఫిర్యాదు.",
            english_complaint="Noise pollution complaint.",
            db_path=self.db_path
        )
        self.assertIsInstance(cid, int)
        self.assertGreater(cid, 0)

        # 2. Get complaint by ID
        complaint = get_complaint_by_id(cid, db_path=self.db_path)
        self.assertIsNotNone(complaint)
        self.assertEqual(complaint[2], "John Doe")

        # 3. Update storage and audio path
        update_audio_path(cid, "audio/new_audio.webm", db_path=self.db_path)
        update_complaint_storage(
            complaint_id=cid,
            storage_backend="local",
            audio_path="audio/new_audio.webm",
            telugu_pdf_path="generated/telugu.pdf",
            english_pdf_path="generated/english.pdf",
            db_path=self.db_path
        )
        storage_info = get_complaint_storage_info(cid, db_path=self.db_path)
        self.assertEqual(storage_info["audio_path"], "audio/new_audio.webm")
        self.assertEqual(storage_info["telugu_pdf_path"], "generated/telugu.pdf")

        # 4. Complaints listing
        all_complaints = get_complaints(db_path=self.db_path)
        self.assertGreaterEqual(len(all_complaints), 1)

        # 5. Statistics
        total, today, month = get_statistics()
        self.assertIsInstance(total, int)

        # 6. Login attempt tracking & lockout analysis
        attempt_id = record_login_attempt("testuser", "192.168.1.50", success=False, db_path=self.db_path)
        self.assertIsInstance(attempt_id, int)
        is_locked, remaining = is_login_locked("testuser", "192.168.1.50", db_path=self.db_path)
        self.assertFalse(is_locked)
        clear_failed_login_attempts("testuser", db_path=self.db_path)


if __name__ == "__main__":
    unittest.main()

