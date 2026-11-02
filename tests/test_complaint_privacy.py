"""
Tests for SEC-03 Complaint Privacy and Cross-Session Data Isolation.
Verifies removal of module-level global complaint state (latest_english),
per-session complaint retrieval from SQLite, and robust RBAC boundaries.
Uses isolated temporary SQLite database and independent Flask test client sessions.
"""

import os
import io
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
import backend.routes.complaints as complaints_module
from backend.services.database import init_db, create_officer, save_complaint, get_complaint_by_id
from backend.services.auth import generate_password_hash


class TestComplaintPrivacy(unittest.TestCase):

    def setUp(self):
        """Set up an isolated temporary database, Flask app, and test accounts."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        init_db(self.temp_db_path)

        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.temp_db_path)
        self.db_patcher.start()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["DATABASE_PATH"] = self.temp_db_path

        # Provision distinct test accounts
        self.admin_id = create_officer(
            username="privacy_admin",
            password_hash=generate_password_hash("AdminPass123!"),
            full_name="Privacy Admin",
            role="admin",
            db_path=self.temp_db_path
        )

        self.officer_a_id = create_officer(
            username="officer_alpha",
            password_hash=generate_password_hash("OfficerPass123!"),
            full_name="Officer Alpha",
            role="officer",
            db_path=self.temp_db_path
        )

        self.officer_b_id = create_officer(
            username="officer_beta",
            password_hash=generate_password_hash("OfficerPass123!"),
            full_name="Officer Beta",
            role="officer",
            db_path=self.temp_db_path
        )

        self.viewer_id = create_officer(
            username="viewer_user",
            password_hash=generate_password_hash("ViewerPass123!"),
            full_name="Viewer User",
            role="viewer",
            db_path=self.temp_db_path
        )

        self.created_dirs = []
        self.created_files = []

    def tearDown(self):
        """Clean up isolated database, patchers, and created files."""
        self.db_patcher.stop()

        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

        for d in self.created_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)

        for f in self.created_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

        # Clean up any synthetic test records created in case_records/2026/November
        nov_dir = os.path.join("case_records", "2026", "November")
        if os.path.exists(nov_dir):
            shutil.rmtree(nov_dir, ignore_errors=True)

    def _login_client(self, username, role, officer_id):
        """Create an authenticated Flask test client for a specific user session."""
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["officer_id"] = officer_id
            sess["username"] = username
            sess["role"] = role
        return client

    def _get_csrf_token(self, client, endpoint="/record") -> str:
        """Fetch CSRF token from a protected form page."""
        resp = client.get(endpoint)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', resp.data.decode("utf-8"))
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', resp.data.decode("utf-8"))
        return match.group(1) if match else ""

    def _process_sample_complaint(self, client, complainant_name, english_text, telugu_text="టెక్స్ట్"):
        """Helper to simulate complaint submission through /process for a client."""
        csrf_token = self._get_csrf_token(client, "/record")
        fake_audio = io.BytesIO(b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00data\x00\x00\x00\x00")
        filename = f"audio_{complainant_name.replace(' ', '_').lower()}.wav"
        temp_audio_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        self.created_files.append(temp_audio_path)

        data = {
            "csrf_token": csrf_token,
            "complainant_name": complainant_name,
            "phone_number": "9123456789",
            "audio": (fake_audio, filename)
        }

        with patch("backend.routes.complaints.speech_to_text", return_value="నమూనా ఆడియో"), \
             patch("backend.routes.complaints.clean_speech", return_value="నమూనా ఆడియో"), \
             patch("backend.routes.complaints.generate_complaint", return_value=telugu_text), \
             patch("backend.routes.complaints.translate_to_english", return_value=english_text), \
             patch("backend.routes.complaints.generate_subject", return_value=f"Subject for {complainant_name}"), \
             patch("backend.routes.complaints.generate_telugu_pdf"), \
             patch("backend.routes.complaints.generate_english_pdf"), \
             patch.object(Config, "STORAGE_BACKEND", "local"):
            response = client.post(
                "/process",
                data=data,
                content_type="multipart/form-data"
            )
        return response

    def test_01_no_module_level_global_complaint_state(self):
        """1. Verify module-level 'latest_english' global variable has been completely removed."""
        self.assertFalse(
            hasattr(complaints_module, "latest_english"),
            "CRITICAL: complaints_module still has 'latest_english' global variable!"
        )

    def test_02_officer_a_and_officer_b_session_isolation(self):
        """
        2. Verify multi-officer isolation:
           - Officer A creates complaint A.
           - Officer B creates complaint B.
           - Officer A sees complaint A on /english.
           - Officer B sees complaint B on /english.
           - Neither officer sees the other's complaint on /english.
        """
        client_a = self._login_client("officer_alpha", "officer", self.officer_a_id)
        client_b = self._login_client("officer_beta", "officer", self.officer_b_id)

        text_a = "Officer Alpha Confidential Report - Incident AAAAA"
        text_b = "Officer Beta Confidential Report - Incident BBBBB"

        # Officer A creates complaint A
        resp_a = self._process_sample_complaint(client_a, "Citizen Ramesh", text_a)
        self.assertEqual(resp_a.status_code, 200)

        # Officer B creates complaint B
        resp_b = self._process_sample_complaint(client_b, "Citizen Sita", text_b)
        self.assertEqual(resp_b.status_code, 200)

        # Verify Officer A accesses /english -> sees ONLY complaint A
        view_a = client_a.get("/english")
        self.assertEqual(view_a.status_code, 200)
        content_a = view_a.data.decode("utf-8")
        self.assertIn(text_a, content_a)
        self.assertIn("Citizen Ramesh", content_a)
        self.assertNotIn(text_b, content_a)
        self.assertNotIn("Citizen Sita", content_a)

        # Verify Officer B accesses /english -> sees ONLY complaint B
        view_b = client_b.get("/english")
        self.assertEqual(view_b.status_code, 200)
        content_b = view_b.data.decode("utf-8")
        self.assertIn(text_b, content_b)
        self.assertIn("Citizen Sita", content_b)
        self.assertNotIn(text_a, content_b)
        self.assertNotIn("Citizen Ramesh", content_b)

    def test_03_officer_a_cannot_see_subsequent_officer_b_complaint(self):
        """
        3. Verify that after Officer B processes a new complaint, Officer A's /english
        page STILL displays Officer A's complaint (no overwrite by later requests).
        """
        client_a = self._login_client("officer_alpha", "officer", self.officer_a_id)
        client_b = self._login_client("officer_beta", "officer", self.officer_b_id)

        text_a = "First Complaint By Alpha - Code 111"
        text_b = "Second Complaint By Beta - Code 222"

        self._process_sample_complaint(client_a, "Complainant 1", text_a)
        self._process_sample_complaint(client_b, "Complainant 2", text_b)

        # Re-fetch Officer A's /english after Officer B's creation
        view_a = client_a.get("/english")
        content_a = view_a.data.decode("utf-8")
        self.assertIn(text_a, content_a)
        self.assertNotIn(text_b, content_a)

    def test_04_session_stores_only_complaint_id_never_full_text(self):
        """
        4. Verify session storage contains only the integer complaint ID,
        and never leaks full complaint text, citizen names, or sensitive details into session cookies.
        """
        client = self._login_client("officer_alpha", "officer", self.officer_a_id)
        unique_secret_text = "SECRET_CLASSIFIED_EVIDENCE_98765"
        self._process_sample_complaint(client, "Confidential Complainant", unique_secret_text)

        with client.session_transaction() as sess:
            latest_id = sess.get("latest_complaint_id")
            self.assertIsInstance(latest_id, int)
            self.assertGreater(latest_id, 0)
            # Verify no string field in the session contains the secret complaint text
            for key, val in sess.items():
                if isinstance(val, str):
                    self.assertNotIn(unique_secret_text, val)
                    self.assertNotIn("Confidential Complainant", val)

    def test_05_missing_session_complaint_id_handled_safely(self):
        """
        5. Verify that accessing /english without having processed a complaint
        in the current session returns a safe notice and does not leak previous data or 500 error.
        """
        client = self._login_client("officer_alpha", "officer", self.officer_a_id)
        # Fresh session with no 'latest_complaint_id'
        resp = client.get("/english")
        self.assertEqual(resp.status_code, 200)
        content = resp.data.decode("utf-8")
        self.assertIn("No recent complaint found in this session", content)

    def test_06_invalid_or_corrupted_session_complaint_id_handled_safely(self):
        """
        6. Verify that non-existent, negative, or non-integer complaint IDs
        stored in session are handled safely with an informative error message.
        """
        client = self._login_client("officer_alpha", "officer", self.officer_a_id)

        # Test non-existent ID
        with client.session_transaction() as sess:
            sess["latest_complaint_id"] = 999999
        resp = client.get("/english")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Complaint record not found", resp.data.decode("utf-8"))

        # Test non-integer string ID
        with client.session_transaction() as sess:
            sess["latest_complaint_id"] = "not_a_valid_number"
        resp2 = client.get("/english")
        self.assertEqual(resp2.status_code, 200)
        self.assertIn("Invalid complaint identifier", resp2.data.decode("utf-8"))

    def test_07_viewer_cannot_create_or_process_complaints(self):
        """
        7. Verify RBAC enforcement: Viewer role cannot access /record (403)
        or submit to /process (403).
        """
        viewer_client = self._login_client("viewer_user", "viewer", self.viewer_id)

        # GET /record is denied 403
        resp_get = viewer_client.get("/record")
        self.assertEqual(resp_get.status_code, 403)

        # POST /process with valid CSRF token is denied 403 by RBAC
        csrf_token = self._get_csrf_token(viewer_client, endpoint="/")
        resp_post = viewer_client.post(
            "/process",
            data={
                "csrf_token": csrf_token,
                "complainant_name": "Unauthorized Test",
                "phone_number": "9000000000"
            }
        )
        self.assertEqual(resp_post.status_code, 403)
        self.assertIn("Access Denied", resp_post.data.decode("utf-8"))

    def test_08_existing_english_complaint_viewing_works(self):
        """
        8. Verify /view_english/<id> continues to work properly for both
        Officer and Viewer roles, rendering all station metadata and case information.
        """
        # Seed a complaint in the isolated test DB
        cid = save_complaint(
            registered_on="2026-11-02 11:00:00",
            english_name="Test Citizen Alpha",
            telugu_name="టెస్ట్ సిటిజన్ ఆల్ఫా",
            phone="9876501234",
            subject="Lost Wallet",
            audio_path="audio/test_audio.webm",
            telugu_complaint="నా పర్స్ పోయింది.",
            english_complaint="My wallet was lost near the bus stop.",
            db_path=self.temp_db_path
        )

        officer_client = self._login_client("officer_alpha", "officer", self.officer_a_id)
        resp_off = officer_client.get(f"/view_english/{cid}")
        self.assertEqual(resp_off.status_code, 200)
        content_off = resp_off.data.decode("utf-8")
        self.assertIn("Test Citizen Alpha", content_off)
        self.assertIn("My wallet was lost near the bus stop", content_off)
        self.assertIn("Case ID", content_off)

        viewer_client = self._login_client("viewer_user", "viewer", self.viewer_id)
        resp_view = viewer_client.get(f"/view_english/{cid}")
        self.assertEqual(resp_view.status_code, 200)
        self.assertIn("Test Citizen Alpha", resp_view.data.decode("utf-8"))

    def test_09_admin_and_officer_functionality_intact(self):
        """
        9. Verify Admin has full ability to process complaints and view /english
        and /view_english/<id>, maintaining complete RBAC compatibility.
        """
        admin_client = self._login_client("privacy_admin", "admin", self.admin_id)

        admin_text = "Admin Created High Priority Incident Report"
        resp = self._process_sample_complaint(admin_client, "Admin Citizen", admin_text)
        self.assertEqual(resp.status_code, 200)

        view_admin = admin_client.get("/english")
        self.assertEqual(view_admin.status_code, 200)
        content = view_admin.data.decode("utf-8")
        self.assertIn(admin_text, content)
        self.assertIn("Admin Citizen", content)

    def test_10_unauthenticated_access_to_english_redirects_to_login(self):
        """
        10. Verify unauthenticated requests to /english are redirected to /login.
        """
        anon_client = self.app.test_client()
        resp = anon_client.get("/english")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))


if __name__ == "__main__":
    unittest.main()
