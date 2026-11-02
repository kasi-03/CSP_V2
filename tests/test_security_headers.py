"""
Tests for SEC-05: HTTP Security Headers and Content Security Policy (CSP).
Verifies:
- CSP (Content-Security-Policy) header directives and Report-Only toggle.
- X-Frame-Options: DENY (clickjacking protection).
- X-Content-Type-Options: nosniff (MIME sniffing defense).
- Referrer-Policy: strict-origin-when-cross-origin.
- Permissions-Policy preserving microphone=(self) for voice complaints.
- HSTS (Strict-Transport-Security) enabled on HTTPS/production, omitted on local HTTP.
- Authentication, CSRF, RBAC, static assets, and PDF generation functionality intact.
Uses an isolated temporary SQLite database and synthetic test accounts.
"""

import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, create_officer, save_complaint
from backend.services.auth import generate_password_hash
from backend.services.pdf_generator import generate_telugu_pdf, generate_english_pdf


class TestSecurityHeaders(unittest.TestCase):

    def setUp(self):
        """Set up an isolated temporary database, app instance, and test users."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        init_db(self.temp_db_path)

        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.temp_db_path)
        self.db_patcher.start()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["DATABASE_PATH"] = self.temp_db_path

        # Provision test accounts
        self.admin_id = create_officer(
            username="headers_admin",
            password_hash=generate_password_hash("HeaderAdminPass123!"),
            full_name="Header Admin Officer",
            role="admin",
            db_path=self.temp_db_path
        )

        self.officer_id = create_officer(
            username="headers_officer",
            password_hash=generate_password_hash("HeaderOfficerPass123!"),
            full_name="Header Officer",
            role="officer",
            db_path=self.temp_db_path
        )

        self.viewer_id = create_officer(
            username="headers_viewer",
            password_hash=generate_password_hash("HeaderViewerPass123!"),
            full_name="Header Viewer",
            role="viewer",
            db_path=self.temp_db_path
        )

        self.created_files = []
        self.created_dirs = []

    def tearDown(self):
        """Clean up isolated database, patchers, and created files."""
        self.db_patcher.stop()

        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

        for f in self.created_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

        for d in self.created_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)

        nov_dir = os.path.join("case_records", "2026", "November")
        if os.path.exists(nov_dir):
            shutil.rmtree(nov_dir, ignore_errors=True)

    def _login_client(self, username, role, officer_id):
        """Helper to create an authenticated Flask test client."""
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["officer_id"] = officer_id
            sess["username"] = username
            sess["role"] = role
        return client

    def _get_csrf_token(self, client, endpoint="/login") -> str:
        """Helper to extract CSRF token from a form page."""
        resp = client.get(endpoint)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', resp.data.decode("utf-8"))
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', resp.data.decode("utf-8"))
        return match.group(1) if match else ""

    def test_01_core_security_headers_present(self):
        """1. Verify presence of all required HTTP security headers on application responses."""
        client = self.app.test_client()
        resp = client.get("/login")

        self.assertEqual(resp.status_code, 200)

        # Core headers verification
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Permissions-Policy", resp.headers)

    def test_02_csp_directives_validation(self):
        """2. Verify CSP policy directives adhere to least-privilege standards without unsafe-eval."""
        client = self.app.test_client()
        resp = client.get("/login")

        csp = resp.headers.get("Content-Security-Policy", "")

        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self' 'unsafe-inline'", csp)
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)
        self.assertIn("img-src 'self' data:", csp)
        self.assertIn("font-src 'self' data:", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("media-src 'self' blob:", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("form-action 'self'", csp)

        # Ensure unsafe-eval is strictly prohibited
        self.assertNotIn("'unsafe-eval'", csp)
        # Ensure wildcard scripts/styles are prohibited
        self.assertNotIn("script-src *", csp)
        self.assertNotIn("style-src *", csp)

    def test_03_csp_report_only_toggle(self):
        """3. Verify CSP_REPORT_ONLY config switches header to Content-Security-Policy-Report-Only."""
        self.app.config["CSP_REPORT_ONLY"] = True
        client = self.app.test_client()
        resp = client.get("/login")

        self.assertIn("Content-Security-Policy-Report-Only", resp.headers)
        self.assertNotIn("Content-Security-Policy", resp.headers)

        # Revert toggle
        self.app.config["CSP_REPORT_ONLY"] = False
        resp2 = client.get("/login")
        self.assertIn("Content-Security-Policy", resp2.headers)
        self.assertNotIn("Content-Security-Policy-Report-Only", resp2.headers)

    def test_04_permissions_policy_preserves_microphone(self):
        """4. Verify Permissions-Policy preserves microphone access for self and blocks others."""
        client = self.app.test_client()
        resp = client.get("/login")

        policy = resp.headers.get("Permissions-Policy", "")
        self.assertIn("microphone=(self)", policy)
        self.assertIn("camera=()", policy)
        self.assertIn("geolocation=()", policy)
        self.assertIn("payment=()", policy)
        self.assertIn("usb=()", policy)

    def test_05_hsts_behavior_http_vs_https(self):
        """5. Verify HSTS is omitted on local HTTP development and present on production HTTPS."""
        client = self.app.test_client()

        # 5a. Ordinary local HTTP request -> HSTS MUST BE ABSENT
        resp_http = client.get("/login")
        self.assertNotIn("Strict-Transport-Security", resp_http.headers)

        # 5b. HTTPS request -> HSTS MUST BE PRESENT with exact max-age without includeSubDomains
        resp_https = client.get("/login", base_url="https://localhost")
        self.assertIn("Strict-Transport-Security", resp_https.headers)
        hsts_value = resp_https.headers.get("Strict-Transport-Security", "")
        self.assertEqual(hsts_value, "max-age=31536000")
        # Verify no includeSubDomains or preload
        self.assertNotIn("includeSubDomains", hsts_value)
        self.assertNotIn("preload", hsts_value)

        # 5c. Production config simulation with HSTS_ENABLED=True & SESSION_COOKIE_SECURE=True
        self.app.config["HSTS_ENABLED"] = True
        self.app.config["SESSION_COOKIE_SECURE"] = True
        resp_prod = client.get("/login")
        self.assertIn("Strict-Transport-Security", resp_prod.headers)

        # Revert config
        self.app.config["HSTS_ENABLED"] = False
        self.app.config["SESSION_COOKIE_SECURE"] = False

    def test_06_login_and_logout_flow_with_security_headers(self):
        """6. Verify authentication POST routes process correctly while attaching security headers."""
        client = self.app.test_client()
        csrf_token = self._get_csrf_token(client, "/login")

        # Submit login
        login_resp = client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "username": "headers_officer",
                "password": "HeaderOfficerPass123!"
            },
            follow_redirects=False
        )
        self.assertEqual(login_resp.status_code, 302)
        self.assertEqual(login_resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(login_resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", login_resp.headers)

        # Access dashboard as logged in user
        dash_resp = client.get("/")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertEqual(dash_resp.headers.get("X-Frame-Options"), "DENY")

        # Logout
        csrf_logout = self._get_csrf_token(client, "/")
        logout_resp = client.post(
            "/logout",
            data={"csrf_token": csrf_logout},
            follow_redirects=False
        )
        self.assertEqual(logout_resp.status_code, 302)
        self.assertIn("Content-Security-Policy", logout_resp.headers)

    def test_07_csrf_protection_and_error_responses_include_headers(self):
        """7. Verify security headers are attached even on CSRF error (400) and auth failure (401)."""
        client = self.app.test_client()

        # Missing CSRF -> 400 Bad Request
        resp_csrf_fail = client.post("/login", data={"username": "test"})
        self.assertEqual(resp_csrf_fail.status_code, 400)
        self.assertEqual(resp_csrf_fail.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", resp_csrf_fail.headers)

        # Invalid credentials -> 401 Unauthorized
        csrf_token = self._get_csrf_token(client, "/login")
        resp_auth_fail = client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "username": "headers_officer",
                "password": "WrongPassword999!"
            }
        )
        self.assertEqual(resp_auth_fail.status_code, 401)
        self.assertEqual(resp_auth_fail.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("Content-Security-Policy", resp_auth_fail.headers)

    def test_08_rbac_pages_function_with_headers(self):
        """8. Verify Admin, Officer, and Viewer pages function correctly with security headers."""
        admin_client = self._login_client("headers_admin", "admin", self.admin_id)
        officer_client = self._login_client("headers_officer", "officer", self.officer_id)
        viewer_client = self._login_client("headers_viewer", "viewer", self.viewer_id)

        # Admin route
        resp_admin = admin_client.get("/admin/officers")
        self.assertEqual(resp_admin.status_code, 200)
        self.assertEqual(resp_admin.headers.get("X-Frame-Options"), "DENY")

        # Officer route
        resp_officer = officer_client.get("/record")
        self.assertEqual(resp_officer.status_code, 200)
        self.assertIn("Content-Security-Policy", resp_officer.headers)

        # Viewer route (read-only allowed)
        resp_viewer = viewer_client.get("/")
        self.assertEqual(resp_viewer.status_code, 200)
        self.assertEqual(resp_viewer.headers.get("X-Frame-Options"), "DENY")

        # Viewer denied on protected route (403)
        resp_viewer_denied = viewer_client.get("/record")
        self.assertEqual(resp_viewer_denied.status_code, 403)
        self.assertIn("Content-Security-Policy", resp_viewer_denied.headers)

    def test_09_static_assets_and_complaint_views(self):
        """9. Verify static assets (CSS, JS, fonts) and complaint views render with security headers."""
        cid = save_complaint(
            registered_on="2026-11-02 12:30:00",
            english_name="Header Citizen",
            telugu_name="హెడర్ సిటిజెన్",
            phone="9988776655",
            subject="Header Inspection",
            audio_path="audio/test_audio.webm",
            telugu_complaint="ఫిర్యాదు సమాచారం",
            english_complaint="Complaint information details",
            db_path=self.temp_db_path
        )

        officer_client = self._login_client("headers_officer", "officer", self.officer_id)

        # View Telugu & English
        resp_te = officer_client.get(f"/view_telugu/{cid}")
        self.assertEqual(resp_te.status_code, 200)
        self.assertIn("Content-Security-Policy", resp_te.headers)

        resp_en = officer_client.get(f"/view_english/{cid}")
        self.assertEqual(resp_en.status_code, 200)
        self.assertIn("Content-Security-Policy", resp_en.headers)

        # Static assets
        for asset in ["/static/css/common.css", "/static/css/complaint.css", "/static/js/record.js"]:
            resp_asset = self.app.test_client().get(asset)
            self.assertEqual(resp_asset.status_code, 200)
            self.assertEqual(resp_asset.headers.get("X-Content-Type-Options"), "nosniff")

    def test_10_pdf_generation_unaffected_by_security_headers(self):
        """10. Verify PDF generation functions continue working seamlessly with security headers active."""
        cid = save_complaint(
            registered_on="2026-11-02 13:00:00",
            english_name="PDF Citizen",
            telugu_name="పిడిఎఫ్ సిటిజెన్",
            phone="9123456780",
            subject="PDF Generation Test",
            audio_path="audio/test_audio.webm",
            telugu_complaint="పిడిఎఫ్ వివరాలు",
            english_complaint="PDF details text",
            db_path=self.temp_db_path
        )

        out_te = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False).name
        out_en = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False).name
        self.created_files.extend([out_te, out_en])

        try:
            generate_telugu_pdf(out_te, cid, db_path=self.temp_db_path)
            self.assertTrue(os.path.exists(out_te))
            self.assertGreater(os.path.getsize(out_te), 1000)

            generate_english_pdf(out_en, cid, db_path=self.temp_db_path)
            self.assertTrue(os.path.exists(out_en))
            self.assertGreater(os.path.getsize(out_en), 1000)
        except Exception as e:
            self.fail(f"PDF generation failed with security headers active: {e}")


if __name__ == "__main__":
    unittest.main()

