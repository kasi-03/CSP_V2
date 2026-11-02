"""
tests/test_session_cleanup.py
=============================
Comprehensive test suite for Phase 6.2.9 - SEC-09: Safe Filesystem Session Cleanup.

Verifies:
1. Session lifetime and security configuration (60 min, HttpOnly, Lax, permanent, threshold=500).
2. Built-in expiration on read: Cachelib natively invalidates expired sessions.
3. Maintenance cleanup safely removes expired session files using standard library operations.
4. Active/unexpired session files are strictly preserved and remain readable.
5. Management files (.fs_count, .cleanup.lock) are never deleted.
6. Multi-process safety: SessionProcessLock prevents concurrent execution across Gunicorn workers.
7. Concurrent read/write and cleanup execution do not produce race conditions.
8. Full officer authentication lifecycle (login, dashboard access, cleanup, logout).
9. Zero session ID, token, or content exposure in logs.
10. Production session directory and files are preserved.
"""

import io
import logging
import os
import shutil
import struct
import tempfile
import threading
import time
from datetime import timedelta
import unittest

from backend import create_app
from backend.services.database import init_db, create_officer
from backend.services.session_service import (
    SessionProcessLock,
    cleanup_expired_sessions,
    get_session_cache,
    is_cachelib_format_compatible,
    resolve_session_dir,
)
from config import Config


class TestSessionConfig(Config):
    """Test configuration using isolated temporary folders."""
    TESTING = True
    WTF_CSRF_ENABLED = False


class TestSessionCleanup(unittest.TestCase):
    """Focused test suite for filesystem session cleanup and lifetime management."""

    def setUp(self):
        """Create isolated temporary directories for database and sessions."""
        self.test_dir = tempfile.mkdtemp(prefix="csp_session_test_")
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.session_dir = os.path.join(self.test_dir, ".flask_session")
        os.makedirs(self.session_dir, exist_ok=True)

        init_db(self.db_path)

        class CustomConfig(TestSessionConfig):
            DATABASE_PATH = self.db_path
            SESSION_FILE_DIR = self.session_dir
            SESSION_FILE_THRESHOLD = 500
            PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
            SESSION_CLEANUP_INTERVAL_MINUTES = 15

        self.config_class = CustomConfig
        self.app = create_app(self.config_class)
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up isolated test directories."""
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except OSError:
                pass

    def test_01_session_configuration_and_lifetime(self):
        """1. Verify session lifetime and security parameters are correctly configured."""
        self.assertEqual(self.app.config["SESSION_TYPE"], "filesystem")
        self.assertTrue(self.app.config["SESSION_PERMANENT"])
        self.assertEqual(self.app.config["PERMANENT_SESSION_LIFETIME"], timedelta(minutes=60))
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertEqual(self.app.config["SESSION_FILE_THRESHOLD"], 500)
        self.assertTrue(self.app.config.get("SESSION_USE_SIGNER", False))

    def test_02_builtin_expiration_on_read(self):
        """2. Verify Cachelib's built-in expiration natively returns None for expired sessions."""
        cache = get_session_cache(self.app)
        self.assertIsNotNone(cache, "Session cache must be accessible")

        # 1. Set an active session with valid lifetime
        cache.set("active_test_key", {"data": "test_payload"}, timeout=300)
        val_active = cache.get("active_test_key")
        self.assertEqual(val_active, {"data": "test_payload"})

        # 2. Write an expired session file directly into cache directory
        expired_fname = cache._get_filename("expired_test_key")
        past_timestamp = int(time.time()) - 100
        with open(expired_fname, "wb") as f:
            f.write(struct.pack("I", past_timestamp))
            cache.serializer.dump({"data": "expired_payload"}, f)

        # 3. Built-in read: Cachelib natively checks timestamp and returns None
        val_expired = cache.get("expired_test_key")
        self.assertIsNone(val_expired, "Built-in cache engine must invalidate expired sessions on read")

    def test_03_maintenance_cleanup_removes_expired_files(self):
        """3. Verify expired session files are safely removed from the filesystem."""
        cache = get_session_cache(self.app)
        self.assertIsNotNone(cache)

        # Manually create an expired session file (timestamp in the past)
        expired_filepath = os.path.join(self.session_dir, "sess_expired_test_file")
        past_time = int(time.time()) - 300  # 5 minutes ago

        with open(expired_filepath, "wb") as f:
            f.write(struct.pack("I", past_time))
            cache.serializer.dump({"officer": "past_session"}, f)

        self.assertTrue(os.path.exists(expired_filepath), "Expired session file must exist before cleanup")

        # Execute cleanup
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)

        self.assertEqual(removed, 1, "Exactly one expired session file must be removed")
        self.assertEqual(remaining, 0, "Zero active sessions should remain")
        self.assertFalse(os.path.exists(expired_filepath), "Expired session file must be removed from disk")

    def test_04_active_sessions_remain_intact_and_readable(self):
        """4. Verify active sessions are never deleted and remain readable on disk."""
        cache = get_session_cache(self.app)
        self.assertIsNotNone(cache)

        # Write an active session valid for 3600 seconds
        cache.set("active_key_test", {"officer": "active_officer", "badge": "POL-1001"}, timeout=3600)

        # Execute cleanup
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)

        self.assertEqual(removed, 0, "No active sessions should be removed")
        self.assertEqual(remaining, 1, "Active session must be counted as remaining")

        # Confirm data integrity via cache
        active_val = cache.get("active_key_test")
        self.assertIsNotNone(active_val)
        self.assertEqual(active_val.get("officer"), "active_officer")
        self.assertEqual(active_val.get("badge"), "POL-1001")

    def test_05_mixed_active_and_expired_sessions(self):
        """5. Verify only expired files are deleted when mixed with active files."""
        cache = get_session_cache(self.app)
        now = int(time.time())

        # Write 2 active sessions
        cache.set("active_a", {"role": "admin"}, timeout=3600)
        cache.set("active_b", {"role": "officer"}, timeout=1800)

        # Write 2 expired session files directly
        exp1_path = os.path.join(self.session_dir, "sess_exp_1")
        exp2_path = os.path.join(self.session_dir, "sess_exp_2")
        with open(exp1_path, "wb") as f:
            f.write(struct.pack("I", now - 100))
            cache.serializer.dump({"role": "expired1"}, f)
        with open(exp2_path, "wb") as f:
            f.write(struct.pack("I", now - 200))
            cache.serializer.dump({"role": "expired2"}, f)

        self.assertTrue(os.path.exists(exp1_path))
        self.assertTrue(os.path.exists(exp2_path))

        # Run cleanup
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)

        self.assertEqual(removed, 2, "Must remove exactly 2 expired session files")
        self.assertEqual(remaining, 2, "Must retain exactly 2 active session files")

        # Expired files are removed
        self.assertFalse(os.path.exists(exp1_path))
        self.assertFalse(os.path.exists(exp2_path))

        # Active sessions remain readable
        self.assertEqual(cache.get("active_a"), {"role": "admin"})
        self.assertEqual(cache.get("active_b"), {"role": "officer"})

    def test_06_management_files_never_deleted(self):
        """6. Verify management files (.fs_count, .cleanup.lock) are never deleted."""
        # Create management files
        fs_count_path = os.path.join(self.session_dir, ".fs_count")
        with open(fs_count_path, "w") as f:
            f.write("42")

        cleanup_lock_path = os.path.join(self.session_dir, ".cleanup.lock")
        with open(cleanup_lock_path, "w") as f:
            f.write("")

        # Run cleanup
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)

        # Verify management files are intact
        self.assertTrue(os.path.exists(fs_count_path), ".fs_count must never be deleted")
        self.assertTrue(os.path.exists(cleanup_lock_path), ".cleanup.lock must never be deleted")
        self.assertEqual(removed, 0)
        self.assertEqual(remaining, 0)

    def test_07_multiprocess_safety_with_process_lock(self):
        """7. Verify SessionProcessLock coordinates workers and prevents concurrent execution."""
        lock_file = os.path.join(self.session_dir, ".cleanup.lock")
        lock_a = SessionProcessLock(lock_file)
        lock_b = SessionProcessLock(lock_file)

        # Worker A acquires lock
        acquired_a = lock_a.acquire()
        self.assertTrue(acquired_a, "Worker A must acquire lock")

        # Worker B tries to acquire lock on the same file -> must fail non-blocking
        acquired_b = lock_b.acquire()
        self.assertFalse(acquired_b, "Worker B must NOT acquire lock while held by Worker A")

        # While Worker A holds lock, cleanup called by another process immediately returns (0, 0)
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)
        self.assertEqual((removed, remaining), (0, 0), "Cleanup must bail out if lock is held")

        # Worker A releases lock
        lock_a.release()

        # Worker B can now acquire lock
        acquired_b_after = lock_b.acquire()
        self.assertTrue(acquired_b_after, "Worker B must acquire lock after Worker A releases")
        lock_b.release()

    def test_08_concurrent_session_access_and_cleanup(self):
        """8. Verify concurrent session read/write and cleanup execution do not cause race conditions."""
        cache = get_session_cache(self.app)
        errors = []

        def reader_writer_worker(worker_id):
            try:
                for i in range(15):
                    key = f"worker_{worker_id}_key_{i}"
                    cache.set(key, {"worker": worker_id, "iter": i}, timeout=3600)
                    val = cache.get(key)
                    if val is None or val.get("iter") != i:
                        errors.append(f"Data inconsistency in worker {worker_id} iter {i}")
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"Reader/writer error: {e}")

        def cleanup_worker():
            try:
                for _ in range(5):
                    cleanup_expired_sessions(session_dir=self.session_dir)
                    time.sleep(0.01)
            except Exception as e:
                errors.append(f"Cleanup error: {e}")

        threads = [
            threading.Thread(target=reader_writer_worker, args=(1,)),
            threading.Thread(target=reader_writer_worker, args=(2,)),
            threading.Thread(target=cleanup_worker),
            threading.Thread(target=cleanup_worker),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent operations caused errors: {errors}")

    def test_09_login_logout_and_authenticated_requests(self):
        """9. Verify full authentication lifecycle functions cleanly across cleanup cycles."""
        officer_id = create_officer(
            username="session_officer",
            password_hash="pbkdf2:sha256:test",
            full_name="Session Officer",
            role="officer",
            db_path=self.db_path
        )
        self.assertGreater(officer_id, 0)

        # Set session using test client session transaction
        with self.client.session_transaction() as sess:
            sess["officer_id"] = officer_id
            sess["username"] = "session_officer"
            sess["role"] = "officer"

        # Verify authenticated request to dashboard succeeds
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

        # Run cleanup while officer is logged in (session is active)
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)
        self.assertGreaterEqual(remaining, 1, "Active officer session must be preserved")

        # Verify officer is STILL logged in after cleanup
        resp_after_cleanup = self.client.get("/")
        self.assertEqual(resp_after_cleanup.status_code, 200)

        # Log out (POST request for CSRF protection)
        resp_logout = self.client.post("/logout")
        self.assertEqual(resp_logout.status_code, 302)

        # Verify access after logout redirects to login
        resp_after_logout = self.client.get("/")
        self.assertEqual(resp_after_logout.status_code, 302)
        self.assertIn("/login", resp_after_logout.headers.get("Location", ""))

    def test_10_cleanup_logs_never_expose_session_ids_or_contents(self):
        """10. Verify cleanup logging does not leak session IDs, filenames, or user data."""
        cache = get_session_cache(self.app)
        now = int(time.time())

        # Write session with identifiable sensitive contents
        sensitive_token = "SUPER_SECRET_OFFICER_TOKEN_9999"
        cache.set("session_with_secret", {"secret_token": sensitive_token}, timeout=3600)

        # Write expired session
        exp_path = os.path.join(self.session_dir, "expired_secret_session_8888")
        with open(exp_path, "wb") as f:
            f.write(struct.pack("I", now - 60))
            cache.serializer.dump({"secret_token": "EXPIRED_SECRET_VALUE"}, f)

        # Capture logs from session_service
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger("backend.services.session_service")
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        try:
            cleanup_expired_sessions(session_dir=self.session_dir)
            handler.flush()
            log_output = log_stream.getvalue()

            # Ensure zero exposure of sensitive strings or session keys
            self.assertNotIn(sensitive_token, log_output)
            self.assertNotIn("EXPIRED_SECRET_VALUE", log_output)
            self.assertNotIn("session_with_secret", log_output)
            self.assertNotIn("expired_secret_session", log_output)
            self.assertNotIn(exp_path, log_output)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)

    def test_11_production_session_directory_preserved(self):
        """11. Verify production session directory (.flask_session) is preserved and not deleted."""
        prod_dir = resolve_session_dir()
        self.assertIsNotNone(prod_dir)
        self.assertTrue(os.path.exists(prod_dir), f"Production session directory {prod_dir} must exist")
        self.assertTrue(os.path.isdir(prod_dir))

    def test_12_filelock_dependency_pinned_and_consistent(self):
        """12. Verify filelock is explicitly declared and pinned consistently in req.txt and requirements.txt."""
        import re
        for req_filename in ("req.txt", "requirements.txt"):
            req_path = os.path.join(Config.BASE_DIR, req_filename)
            self.assertTrue(os.path.exists(req_path), f"{req_filename} must exist.")

            with open(req_path, "r", encoding="utf-8") as f:
                content = f.read()

            match = re.search(r"^filelock==(\d+\.\d+(?:\.\d+)?)$", content, re.MULTILINE)
            self.assertIsNotNone(
                match,
                f"Expected pinned filelock dependency (filelock==<version>) in {req_filename}."
            )
            pinned_version = match.group(1)
            self.assertEqual(pinned_version, "4.2.6")

    def test_13_cachelib_format_compatibility_safeguard(self):
        """13. Verify compatibility safeguard: format check passes, aborts if incompatible, preserves active."""
        # 1. Format check passes under standard environment
        self.assertTrue(is_cachelib_format_compatible())

        # 2. Truncated header files (< 4 bytes) are skipped and never deleted
        malformed_short = os.path.join(self.session_dir, "malformed_short_file")
        with open(malformed_short, "wb") as f:
            f.write(b"\x01\x02")  # Only 2 bytes

        # 3. Create an expired session file
        cache = get_session_cache(self.app)
        now = int(time.time())
        expired_file = os.path.join(self.session_dir, "safeguard_expired")
        with open(expired_file, "wb") as f:
            f.write(struct.pack("I", now - 60))
            cache.serializer.dump({"test": "data"}, f)

        # 4. If compatibility safeguard fails (e.g. incompatible Cachelib version), cleanup aborts
        from unittest.mock import patch
        with patch("backend.services.session_service.is_cachelib_format_compatible", return_value=False):
            removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)
            self.assertEqual((removed, remaining), (0, 0), "Must abort cleanup if compatibility check fails")
            self.assertTrue(os.path.exists(expired_file), "No files deleted when safeguard trips")

        # 5. Normal cleanup safely deletes only the expired file and preserves truncated file
        removed, remaining = cleanup_expired_sessions(session_dir=self.session_dir)
        self.assertEqual(removed, 1)
        self.assertFalse(os.path.exists(expired_file), "Expired file is cleaned up")
        self.assertTrue(os.path.exists(malformed_short), "Truncated header file is preserved")


if __name__ == "__main__":
    unittest.main()
