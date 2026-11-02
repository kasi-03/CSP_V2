"""
Unit and integration tests for Officer Authentication, Session Management,
CSRF Protection, Brute-Force Lockout, and Administrator CLI (Phase 3).

Guarantees 100% test isolation using temporary SQLite databases and temporary
session directories; strictly prohibits modification of production complaints.db.
"""

import os
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import (
    init_db,
    create_officer,
    get_officer_by_username,
    get_officer_by_id,
    update_officer_status,
    get_audit_logs,
    record_login_attempt,
    get_failed_login_attempts_count,
    is_login_locked,
    clear_failed_login_attempts
)
from backend.services.auth import (
    hash_password,
    verify_password,
    validate_password_strength,
    authenticate_officer,
    get_authenticated_officer
)
from backend.cli import create_admin_interactive


class BaseAuthTestCase(unittest.TestCase):
    """Base setup providing an isolated SQLite database and filesystem session directory."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_auth.db")
        self.session_dir = os.path.join(self.temp_dir, "test_sessions")
        os.makedirs(self.session_dir, exist_ok=True)

        # Patch Config.DATABASE_PATH to protect production complaints.db
        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.db_path)
        self.db_patcher.start()

        # Custom isolated TestConfig
        class TestConfig(Config):
            DATABASE_PATH = self.db_path
            SESSION_FILE_DIR = self.session_dir
            TESTING = True
            WTF_CSRF_ENABLED = True
            SECRET_KEY = "test-secret-key-32-chars-strictly-for-testing"
            MAX_FAILED_LOGIN_ATTEMPTS = 5
            LOCKOUT_DURATION_MINUTES = 15

        self.test_config = TestConfig
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

        # Initialize schema in temporary database
        init_db(self.db_path)

    def tearDown(self):
        self.db_patcher.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def get_test_audit_logs(self, username: str = None):
        """Retrieve audit logs filtered by username from test database."""
        logs = get_audit_logs(limit=200, db_path=self.db_path)
        if username:
            return [l for l in logs if (l.get("username") or "").lower() == username.lower()]
        return logs

    def extract_csrf_token(self, html_content: str) -> str:
        """Extract CSRF token from HTML form hidden input."""
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_content)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', html_content)
        self.assertIsNotNone(match, "CSRF token hidden input must be present in HTML")
        return match.group(1)

    def create_test_officer(
        self,
        username: str = "officer1",
        password: str = "SecurePass123!",
        full_name: str = "Test Officer A",
        badge_number: str = "AP-POL-104",
        role: str = "officer",
        is_active: int = 1
    ) -> int:
        """Helper to create an officer record in the test database."""
        pwd_hash = hash_password(password)
        officer_id = create_officer(
            username=username,
            password_hash=pwd_hash,
            full_name=full_name,
            role=role,
            badge_number=badge_number,
            db_path=self.db_path
        )
        if is_active != 1:
            update_officer_status(officer_id, is_active=is_active, db_path=self.db_path)
        return officer_id


class TestOfficerAuthentication(BaseAuthTestCase):
    """Test suite covering all 12 required authentication & security test scenarios."""

    def test_01_successful_login(self):
        """1. Successful login sets session, updates last_login, logs audit, and redirects."""
        self.create_test_officer(
            username="admin_user",
            password="AdminPassword123!",
            full_name="Chief Administrator",
            badge_number="CHIEF-01",
            role="admin"
        )

        # GET login page to obtain CSRF token
        get_resp = self.client.get("/login")
        self.assertEqual(get_resp.status_code, 200)
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))

        # POST valid credentials
        post_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "admin_user",
            "password": "AdminPassword123!"
        }, follow_redirects=False)

        # Must redirect (302) to dashboard
        self.assertEqual(post_resp.status_code, 302)
        self.assertEqual(post_resp.headers["Location"], "/")

        # Verify session state via test client session context
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "admin_user")
            self.assertEqual(sess.get("full_name"), "Chief Administrator")
            self.assertEqual(sess.get("role"), "admin")
            self.assertEqual(sess.get("badge_number"), "CHIEF-01")
            self.assertIsNotNone(sess.get("officer_id"))

        # Verify dashboard shows logged-in officer full name and badge
        dash_resp = self.client.get("/")
        dash_html = dash_resp.data.decode("utf-8")
        self.assertIn("Chief Administrator", dash_html)
        self.assertIn("CHIEF-01", dash_html)
        self.assertIn("admin", dash_html.lower())
        self.assertIn("Logout", dash_html)

        # Verify last_login updated in database
        officer = get_officer_by_username("admin_user", db_path=self.db_path)
        self.assertIsNotNone(officer["last_login"])

        # Verify audit log recorded LOGIN_SUCCESS
        logs = self.get_test_audit_logs(username="admin_user")
        self.assertTrue(any(log["action"] == "LOGIN_SUCCESS" and log["status"] == "SUCCESS" for log in logs))

        # Test safe next_url redirect
        # Clear session to simulate fresh unauthenticated login with next parameter
        with self.client.session_transaction() as sess:
            sess.clear()

        get_resp = self.client.get("/login?next=/record")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))

        post_next = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "admin_user",
            "password": "AdminPassword123!",
            "next": "/record"
        }, follow_redirects=False)
        self.assertEqual(post_next.status_code, 302)
        self.assertEqual(post_next.headers["Location"], "/record")

        # Test unsafe next_url redirect (open redirect mitigation)
        with self.client.session_transaction() as sess:
            sess.clear()
        get_resp = self.client.get("/login?next=https://attacker.example.com/steal")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        post_unsafe = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "admin_user",
            "password": "AdminPassword123!",
            "next": "https://attacker.example.com/steal"
        }, follow_redirects=False)
        self.assertEqual(post_unsafe.status_code, 302)
        self.assertEqual(post_unsafe.headers["Location"], "/")

    def test_02_incorrect_password(self):
        """2. Incorrect password returns 401 with generic error, logs attempt and audit."""
        self.create_test_officer(username="officer_smith", password="CorrectPassword123!")

        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))

        post_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "officer_smith",
            "password": "WrongPassword999!"
        })

        self.assertEqual(post_resp.status_code, 401)
        resp_html = post_resp.data.decode("utf-8")
        self.assertIn("Invalid username or password.", resp_html)

        # Session must NOT be established
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("officer_id"))

        # Failed attempt recorded
        failed_count = get_failed_login_attempts_count("officer_smith", window_minutes=15, db_path=self.db_path)
        self.assertEqual(failed_count, 1)

        # Audit log recorded LOGIN_FAILED
        logs = self.get_test_audit_logs(username="officer_smith")
        self.assertTrue(any(log["action"] == "LOGIN_FAILED" and log["status"] == "FAILED" for log in logs))

    def test_03_unknown_username(self):
        """3. Non-existent username returns same generic error and 401 (enumeration defense)."""
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))

        post_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "non_existent_user",
            "password": "SomePassword123!"
        })

        self.assertEqual(post_resp.status_code, 401)
        resp_html = post_resp.data.decode("utf-8")
        self.assertIn("Invalid username or password.", resp_html)

        # Session must NOT be established
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("officer_id"))

        # Audit log recorded
        logs = self.get_test_audit_logs(username="non_existent_user")
        self.assertTrue(any(log["action"] == "LOGIN_FAILED" for log in logs))

    def test_04_inactive_account_rejection(self):
        """4. Inactive officer account is rejected with generic error and 401."""
        self.create_test_officer(
            username="suspended_officer",
            password="ValidPassword123!",
            is_active=0
        )

        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))

        post_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "suspended_officer",
            "password": "ValidPassword123!"
        })

        self.assertEqual(post_resp.status_code, 401)
        resp_html = post_resp.data.decode("utf-8")
        # Generic error message to prevent account status enumeration
        self.assertIn("Invalid username or password.", resp_html)

        # Session must NOT be established
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("officer_id"))

        # Audit log recorded LOGIN_FAILED with inactive details
        logs = self.get_test_audit_logs(username="suspended_officer")
        self.assertTrue(any(log["action"] == "LOGIN_FAILED" and "inactive" in str(log.get("details", "")).lower() for log in logs))

    def test_05_logout_functionality(self):
        """5. POST /logout terminates session and redirects; GET /logout is rejected."""
        self.create_test_officer(username="logout_user", password="LogoutPass123!")

        # 1. Login
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "logout_user",
            "password": "LogoutPass123!"
        })

        # Confirm session established
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "logout_user")

        # 2. GET /logout must be rejected with 405 Method Not Allowed (POST-only requirement)
        get_logout_resp = self.client.get("/logout")
        self.assertEqual(get_logout_resp.status_code, 405)

        # 3. Obtain fresh CSRF token from dashboard for POST /logout
        dash_resp = self.client.get("/")
        dash_csrf = self.extract_csrf_token(dash_resp.data.decode("utf-8"))

        # 4. POST /logout
        post_logout_resp = self.client.post("/logout", data={"csrf_token": dash_csrf}, follow_redirects=False)
        self.assertEqual(post_logout_resp.status_code, 302)
        self.assertIn("/login", post_logout_resp.headers["Location"])

        # 5. Confirm session cleared
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("officer_id"))
            self.assertIsNone(sess.get("username"))

        # 6. Confirm unauthenticated request to / redirects to /login
        dash2 = self.client.get("/", follow_redirects=True)
        self.assertIn("Officer Login", dash2.data.decode("utf-8"))

        # 7. Confirm LOGOUT action in audit log
        logs = self.get_test_audit_logs(username="logout_user")
        self.assertTrue(any(log["action"] == "LOGOUT" and log["status"] == "SUCCESS" for log in logs))

    def test_06_session_configuration_and_cookie_security(self):
        """6. Validate session security configuration: lifetime, HttpOnly, SameSite, signer."""
        self.assertEqual(self.app.config.get("SESSION_TYPE"), "filesystem")
        self.assertEqual(self.app.config.get("PERMANENT_SESSION_LIFETIME"), timedelta(minutes=60))
        self.assertTrue(self.app.config.get("SESSION_COOKIE_HTTPONLY"))
        self.assertEqual(self.app.config.get("SESSION_COOKIE_SAMESITE"), "Lax")
        self.assertTrue(self.app.config.get("SESSION_USE_SIGNER"))

    def test_07_session_invalidation_after_account_deactivation(self):
        """7. Deactivated officer's active session is invalidated on the next request."""
        officer_id = self.create_test_officer(
            username="deactivate_me",
            password="Password123!",
            full_name="Officer Active"
        )

        # 1. Login
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "deactivate_me",
            "password": "Password123!"
        })

        # Verify active session
        dash1 = self.client.get("/")
        self.assertIn("Officer Active", dash1.data.decode("utf-8"))

        # 2. Deactivate officer in database
        update_officer_status(officer_id, is_active=0, db_path=self.db_path)

        # 3. Next request should detect inactive account via before_request, clear session and redirect to /login
        dash2 = self.client.get("/", follow_redirects=True)
        dash2_html = dash2.data.decode("utf-8")
        self.assertNotIn("Officer Active", dash2_html)
        self.assertIn("Officer Login", dash2_html)

        # Session should be empty
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("officer_id"))

    def test_08_csrf_validation(self):
        """8. POST requests without valid CSRF token are rejected with 400 Bad Request."""
        self.create_test_officer(username="csrf_target", password="TargetPassword123!")

        # 1. POST /login without CSRF token -> 400
        resp_no_csrf = self.client.post("/login", data={
            "username": "csrf_target",
            "password": "TargetPassword123!"
        })
        self.assertEqual(resp_no_csrf.status_code, 400)

        # 2. POST /login with invalid/tampered CSRF token -> 400
        resp_bad_csrf = self.client.post("/login", data={
            "csrf_token": "tampered-invalid-csrf-token",
            "username": "csrf_target",
            "password": "TargetPassword123!"
        })
        self.assertEqual(resp_bad_csrf.status_code, 400)

        # 3. POST /logout without CSRF token -> 400
        resp_logout_no_csrf = self.client.post("/logout", data={})
        self.assertEqual(resp_logout_no_csrf.status_code, 400)

        # 4. POST /save_settings without CSRF token -> 400
        resp_settings_no_csrf = self.client.post("/save_settings", data={
            "station_name": "Test Station",
            "place": "Test Place",
            "district": "Test District"
        })
        self.assertEqual(resp_settings_no_csrf.status_code, 400)

        # 5. POST /process without CSRF token -> 400
        resp_process_no_csrf = self.client.post("/process", data={
            "complainant_name": "Test Citizen",
            "phone_number": "9000000000"
        })
        self.assertEqual(resp_process_no_csrf.status_code, 400)

        # 6. POST /save_settings with valid CSRF token from /settings succeeds (requires admin)
        self.create_test_officer(username="admin_csrf", password="AdminPassword123!", role="admin")
        get_login = self.client.get("/login")
        login_csrf = self.extract_csrf_token(get_login.data.decode("utf-8"))
        self.client.post("/login", data={
            "csrf_token": login_csrf,
            "username": "admin_csrf",
            "password": "AdminPassword123!"
        })

        get_settings = self.client.get("/settings")
        settings_csrf = self.extract_csrf_token(get_settings.data.decode("utf-8"))
        with patch("backend.routes.settings.save_station") as mock_save:
            resp_settings_valid = self.client.post("/save_settings", data={
                "csrf_token": settings_csrf,
                "station_name": "Test Police Station",
                "place": "Central Division",
                "district": "Metropolitan"
            }, follow_redirects=False)
            self.assertEqual(resp_settings_valid.status_code, 302)
            mock_save.assert_called_once()

    def test_09_persistent_login_lockout(self):
        """9. Lockout triggers after 5 failed attempts, blocks login, and releases when window elapses."""
        self.create_test_officer(username="lockout_victim", password="VictimPassword123!")

        # Perform 5 failed attempts
        for attempt in range(1, 6):
            get_resp = self.client.get("/login")
            csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
            resp = self.client.post("/login", data={
                "csrf_token": csrf_token,
                "username": "lockout_victim",
                "password": "WrongPassword!"
            })
            self.assertEqual(resp.status_code, 401)

        # Verify account is locked
        locked, _ = is_login_locked("lockout_victim", max_attempts=5, window_minutes=15, db_path=self.db_path)
        self.assertTrue(locked)

        # 6th attempt with CORRECT password must still be rejected due to lockout
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        lockout_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "lockout_victim",
            "password": "VictimPassword123!"
        })
        self.assertEqual(lockout_resp.status_code, 401)
        resp_html = lockout_resp.data.decode("utf-8")
        self.assertTrue("failed login attempts" in resp_html.lower() or "locked" in resp_html.lower())

        # Verify audit log contains LOGIN_LOCKED
        logs = self.get_test_audit_logs(username="lockout_victim")
        self.assertTrue(any(log["action"] == "LOGIN_LOCKED" for log in logs))

        # Clear failed attempts (simulating time window elapsed or admin unlock)
        clear_failed_login_attempts("lockout_victim", db_path=self.db_path)
        unlocked, _ = is_login_locked("lockout_victim", max_attempts=5, window_minutes=15, db_path=self.db_path)
        self.assertFalse(unlocked)

        # Now login with correct password should succeed
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        success_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "lockout_victim",
            "password": "VictimPassword123!"
        }, follow_redirects=False)
        self.assertEqual(success_resp.status_code, 302)

    def test_10_admin_cli_provisioning_and_duplicate_prevention(self):
        """10. Admin CLI prevents duplicates, enforces password strength, and prompts for multi-admin."""
        # 1. Test password strength validation
        valid, msg = validate_password_strength("weak")
        self.assertFalse(valid)
        self.assertIn("8 characters", msg)

        valid, msg = validate_password_strength("alllowercase123!")
        self.assertFalse(valid)
        self.assertIn("uppercase", msg)

        valid, msg = validate_password_strength("ALLUPPERCASE123!")
        self.assertFalse(valid)
        self.assertIn("lowercase", msg)

        valid, msg = validate_password_strength("NoDigitsHere!abc")
        self.assertFalse(valid)
        self.assertTrue("number" in msg.lower() or "digit" in msg.lower())

        valid, msg = validate_password_strength("NoSpecialChar123")
        self.assertFalse(valid)
        self.assertTrue("symbol" in msg.lower() or "special" in msg.lower())

        valid, msg = validate_password_strength("ValidPassword123!")
        self.assertTrue(valid)

        # 2. Provision first admin via CLI function
        admin1_id = create_admin_interactive(
            username="cli_admin1",
            full_name="CLI Administrator 1",
            password="StrongAdminPassword123!",
            badge_number="CLI-001",
            force=False,
            db_path=self.db_path
        )
        self.assertGreater(admin1_id, 0)

        # Verify admin exists in test database
        admin1 = get_officer_by_username("cli_admin1", db_path=self.db_path)
        self.assertIsNotNone(admin1)
        self.assertEqual(admin1["role"], "admin")

        # 3. Attempt duplicate username (case-insensitive)
        exit_code_dup = create_admin_interactive(
            username="CLI_ADMIN1",
            full_name="Duplicate Admin",
            password="StrongAdminPassword123!",
            force=True,
            db_path=self.db_path
        )
        self.assertEqual(exit_code_dup, -1)

        # 4. Multi-admin prompt without force: simulate declining ('n')
        with patch("builtins.input", return_value="n"):
            exit_code_declined = create_admin_interactive(
                username="cli_admin2",
                full_name="CLI Administrator 2",
                password="StrongAdminPassword123!",
                force=False,
                db_path=self.db_path
            )
            self.assertEqual(exit_code_declined, -1)

        # 5. Multi-admin with force=True succeeds
        admin2_id = create_admin_interactive(
            username="cli_admin2",
            full_name="CLI Administrator 2",
            password="StrongAdminPassword123!",
            badge_number="CLI-002",
            force=True,
            db_path=self.db_path
        )
        self.assertGreater(admin2_id, 0)
        admin2 = get_officer_by_username("cli_admin2", db_path=self.db_path)
        self.assertIsNotNone(admin2)

    def test_11_password_hash_verification(self):
        """11. Password hashing uses Werkzeug scrypt, generates unique salts, and verifies correctly."""
        raw_password = "SuperSecretPassword123!"
        hash1 = hash_password(raw_password)
        hash2 = hash_password(raw_password)

        # Must use scrypt method
        self.assertTrue(hash1.startswith("scrypt:"), f"Hash must use scrypt, got {hash1[:15]}")
        # Salt must be unique
        self.assertNotEqual(hash1, hash2, "Two hashes of the same password must have different salts")

        # Correct password verifies to True
        self.assertTrue(verify_password(hash1, raw_password))
        self.assertTrue(verify_password(hash2, raw_password))

        # Incorrect password verifies to False
        self.assertFalse(verify_password(hash1, "WrongPassword123!"))
        self.assertFalse(verify_password(hash1, ""))

    def test_12_no_password_or_secret_leakage(self):
        """12. Verify password hashes are never leaked in templates, audit logs, or get_authenticated_officer."""
        raw_pwd = "ConfidentialSecret123!"
        self.create_test_officer(
            username="leak_test_user",
            password=raw_pwd,
            full_name="Secret Agent"
        )

        # 1. Check get_authenticated_officer
        officer = get_officer_by_username("leak_test_user", db_path=self.db_path)
        safe_officer = get_authenticated_officer(officer["id"], db_path=self.db_path)
        self.assertNotIn("password_hash", safe_officer, "password_hash must NOT be in authenticated officer dict")

        # 2. Login and check dashboard HTML
        get_resp = self.client.get("/login")
        csrf_token = self.extract_csrf_token(get_resp.data.decode("utf-8"))
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "leak_test_user",
            "password": raw_pwd
        })

        dash_resp = self.client.get("/")
        dash_content = dash_resp.data.decode("utf-8")
        self.assertNotIn(raw_pwd, dash_content, "Plain password must never appear in HTML")
        self.assertNotIn("scrypt:", dash_content, "Password hash must never appear in HTML")

        # 3. Check login page HTML
        login_resp = self.client.get("/login")
        login_content = login_resp.data.decode("utf-8")
        self.assertNotIn(raw_pwd, login_content)
        self.assertNotIn("scrypt:", login_content)

        # 4. Check audit logs
        logs = self.get_test_audit_logs(username="leak_test_user")
        for log in logs:
            self.assertNotIn(raw_pwd, str(log.get("details", "")), "Plain password must not be in audit logs")
            self.assertNotIn("scrypt:", str(log.get("details", "")), "Password hash must not be in audit logs")

    def test_13_secret_key_session_cookie_and_static_file_security(self):
        """13. Validate SECRET_KEY stability, SESSION_COOKIE_SECURE env toggle, and .flask_session isolation."""
        # 1. SECRET_KEY stability across app instances (never randomly generated on startup)
        app1 = create_app(self.test_config)
        app2 = create_app(self.test_config)
        self.assertEqual(app1.config["SECRET_KEY"], app2.config["SECRET_KEY"])
        self.assertIsNotNone(app1.config["SECRET_KEY"])
        self.assertNotEqual(app1.config["SECRET_KEY"], "")

        # 2. Missing or empty SECRET_KEY raises RuntimeError
        class MissingSecretConfig(self.test_config):
            SECRET_KEY = ""

        with self.assertRaises(RuntimeError):
            create_app(MissingSecretConfig)

        with patch.dict(os.environ, {"SECRET_KEY": ""}):
            with self.assertRaises(RuntimeError):
                from importlib import reload
                import config
                reload(config)

        # Restore valid environment and config
        from importlib import reload
        import config
        reload(config)

        # 3. Verify .env secret strength (at least 32 characters, non-empty)
        env_secret = os.getenv("SECRET_KEY", "")
        self.assertGreaterEqual(len(env_secret.strip()), 32, "SECRET_KEY in .env must be at least 32 characters")

        # 4. SESSION_COOKIE_SECURE configuration logic
        # In production or explicit SESSION_COOKIE_SECURE=true, it is True
        with patch.dict(os.environ, {"FLASK_ENV": "production", "SESSION_COOKIE_SECURE": "false"}):
            reload(config)
            self.assertTrue(config.Config.SESSION_COOKIE_SECURE)

        with patch.dict(os.environ, {"FLASK_ENV": "development", "SESSION_COOKIE_SECURE": "false"}):
            reload(config)
            self.assertFalse(config.Config.SESSION_COOKIE_SECURE)

        # Restore default config
        reload(config)

        # 5. .flask_session is in .gitignore
        gitignore_path = os.path.join(Config.BASE_DIR, ".gitignore")
        self.assertTrue(os.path.exists(gitignore_path))
        with open(gitignore_path, "r", encoding="utf-8") as f:
            gitignore_content = f.read()
        self.assertIn(".flask_session", gitignore_content)

        # 6. Session files are never exposed through static-file routes
        static_resp1 = self.client.get("/static/.flask_session")
        self.assertEqual(static_resp1.status_code, 404)
        static_resp2 = self.client.get("/static/../.flask_session")
        self.assertIn(static_resp2.status_code, (400, 404))


if __name__ == "__main__":
    unittest.main()
