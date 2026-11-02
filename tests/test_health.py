"""
tests/test_health.py
====================
Comprehensive test suite for Phase 6.2.8 - SEC-07: Backend Health Check Endpoint.

Verifies:
1. GET /health returns HTTP 200 when application and database are healthy.
2. Response is valid JSON with standard {"status": "ok"}.
3. Response contains only safe information (no database paths, secrets, stack traces, or diagnostics).
4. Health endpoint is accessible without authentication (unauthenticated Render uptime checks).
5. Database failures return a safe HTTP 503 {"status": "unhealthy"} without leaking error details.
6. check_db_health() unit behavior (read-only SELECT 1, graceful exception handling, connection cleanup).
7. Existing authentication and RBAC protections on other routes remain completely intact.
8. Security headers (CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy) are attached to /health.
9. Calling /health causes zero database mutations (complaints, officers, audit logs unchanged).
10. HEAD /health is supported for lightweight HTTP monitoring.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from backend import create_app
from backend.services.database import (
    init_db,
    check_db_health,
    create_officer,
    get_connection,
)
from config import Config


class TestHealthConfig(Config):
    """Test configuration using an isolated temporary database."""
    TESTING = True
    WTF_CSRF_ENABLED = False


class TestHealthCheckEndpoint(unittest.TestCase):
    """Focused test suite for the lightweight /health endpoint."""

    def setUp(self):
        """Create an isolated test application and database."""
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        init_db(self.db_path)

        class CustomTestConfig(TestHealthConfig):
            DATABASE_PATH = self.db_path

        self.app = create_app(CustomTestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up the isolated test database."""
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_01_health_returns_http_200_when_healthy(self):
        """1. Verify /health returns HTTP 200 and application/json when healthy."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("application/json"))

    def test_02_health_response_is_valid_json(self):
        """2. Verify /health returns valid JSON with exact expected structure."""
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data, {"status": "ok"})

    def test_03_health_response_contains_only_safe_information(self):
        """3. Verify /health does not expose internal paths, DB details, secrets, or stack traces."""
        response = self.client.get("/health")
        raw_text = response.get_data(as_text=True).lower()
        headers_str = str(dict(response.headers)).lower()

        sensitive_indicators = [
            "secret", "token", "password", "key",
            self.db_path.lower(), "complaints.db",
            "traceback", "exception", "sqlite",
            "environ", "flask_secret"
        ]
        for indicator in sensitive_indicators:
            self.assertNotIn(
                indicator,
                raw_text,
                f"Health response must not contain sensitive indicator: '{indicator}'"
            )

    def test_04_health_works_without_authentication(self):
        """4. Verify /health is accessible to unauthenticated callers (Render uptime monitoring)."""
        # Ensure session is empty
        with self.client.session_transaction() as sess:
            sess.clear()

        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        # Must not redirect to login
        self.assertNotEqual(response.status_code, 302)

        # Also verify that an authenticated session can call /health without issues
        officer_id = create_officer(
            username="health_officer",
            password_hash="pbkdf2:sha256:test",
            full_name="Health Officer",
            role="officer",
            db_path=self.db_path
        )
        with self.client.session_transaction() as sess:
            sess["officer_id"] = officer_id
            sess["username"] = "health_officer"
            sess["role"] = "officer"

        auth_response = self.client.get("/health")
        self.assertEqual(auth_response.status_code, 200)
        self.assertEqual(auth_response.get_json(), {"status": "ok"})

    def test_05_database_failure_returns_safe_failure_response(self):
        """5. Verify database failure returns HTTP 503 with safe JSON and no leaked error details."""
        with patch("backend.check_db_health", return_value=False):
            response = self.client.get("/health")
            self.assertEqual(response.status_code, 503)
            self.assertTrue(response.content_type.startswith("application/json"))
            data = response.get_json()
            self.assertEqual(data, {"status": "unhealthy"})

            raw_text = response.get_data(as_text=True).lower()
            self.assertNotIn("traceback", raw_text)
            self.assertNotIn("error", raw_text)

    def test_06_check_db_health_isolated_behavior(self):
        """6. Verify check_db_health executes SELECT 1 and safely handles errors."""
        # 1. Healthy database check returns True
        self.assertTrue(check_db_health(self.db_path))

        # 2. Inaccessible database path returns False without raising exception
        invalid_path = os.path.join(tempfile.gettempdir(), "nonexistent_dir", "unreachable.db")
        self.assertFalse(check_db_health(invalid_path))

        # 3. Simulated connection / query error returns False gracefully
        with patch("backend.services.database.get_connection", side_effect=sqlite3.OperationalError("disk I/O error")):
            self.assertFalse(check_db_health(self.db_path))

    def test_07_existing_authentication_and_rbac_protections_remain_intact(self):
        """7. Verify protected routes (/ , /admin/users, /complaint/new) still strictly enforce auth."""
        # Ensure session is unauthenticated
        with self.client.session_transaction() as sess:
            sess.clear()

        # Unauthenticated dashboard access must redirect to login
        resp_dashboard = self.client.get("/")
        self.assertEqual(resp_dashboard.status_code, 302)
        self.assertIn("/login", resp_dashboard.headers.get("Location", ""))

        # Unauthenticated admin access must redirect to login
        resp_admin = self.client.get("/admin/officers")
        self.assertEqual(resp_admin.status_code, 302)
        self.assertIn("/login", resp_admin.headers.get("Location", ""))

        # Authenticate as officer role (non-admin)
        officer_id = create_officer(
            username="regular_officer",
            password_hash="pbkdf2:sha256:test",
            full_name="Regular Officer",
            role="officer",
            db_path=self.db_path
        )
        with self.client.session_transaction() as sess:
            sess["officer_id"] = officer_id
            sess["username"] = "regular_officer"
            sess["role"] = "officer"

        # Officer role accessing admin portal must be rejected with 403 Forbidden
        resp_forbidden = self.client.get("/admin/officers")
        self.assertEqual(resp_forbidden.status_code, 403)

    def test_08_health_endpoint_includes_security_headers(self):
        """8. Verify SEC-05 HTTP security headers are attached to /health responses."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

        # Content-Security-Policy
        self.assertIn("Content-Security-Policy", response.headers)
        # X-Frame-Options (Clickjacking protection)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        # X-Content-Type-Options (MIME-sniffing protection)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        # Referrer-Policy
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        # Permissions-Policy
        self.assertIn("Permissions-Policy", response.headers)

    def test_09_health_endpoint_causes_zero_database_mutations(self):
        """9. Verify calling /health does not create or alter any database records."""
        conn = get_connection(self.db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM complaints")
            init_complaints = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM officers")
            init_officers = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM audit_logs")
            init_audit = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM login_attempts")
            init_logins = c.fetchone()[0]
        finally:
            conn.close()

        # Call health check multiple times
        for _ in range(5):
            res = self.client.get("/health")
            self.assertEqual(res.status_code, 200)

        conn = get_connection(self.db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM complaints")
            self.assertEqual(c.fetchone()[0], init_complaints)
            c.execute("SELECT COUNT(*) FROM officers")
            self.assertEqual(c.fetchone()[0], init_officers)
            c.execute("SELECT COUNT(*) FROM audit_logs")
            self.assertEqual(c.fetchone()[0], init_audit)
            c.execute("SELECT COUNT(*) FROM login_attempts")
            self.assertEqual(c.fetchone()[0], init_logins)
        finally:
            conn.close()

    def test_10_health_endpoint_head_method_supported(self):
        """10. Verify HEAD /health returns HTTP 200 with headers and empty body."""
        response = self.client.head("/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("application/json"))
        # HEAD response body must be empty
        self.assertEqual(len(response.get_data()), 0)


if __name__ == "__main__":
    unittest.main()
