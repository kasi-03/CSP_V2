"""
Tests for Flask application routes and template rendering via test client.
Uses isolated temporary SQLite database and authenticated test officer.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, create_officer, save_complaint
from backend.services.auth import generate_password_hash


class TestRoutes(unittest.TestCase):

    def setUp(self):
        # Create an isolated temporary database
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        init_db(self.temp_db_path)

        # Seed sample complaint
        save_complaint(
            registered_on="2026-11-01 10:00:00",
            english_name="Test Citizen",
            telugu_name="టెస్ట్ సిటిజెన్",
            phone="9876543210",
            subject="Test Subject",
            audio_path="audio/test.webm",
            telugu_complaint="టెస్ట్ టెక్స్ట్",
            english_complaint="Test text",
            db_path=self.temp_db_path
        )

        # Seed admin officer
        self.admin_id = create_officer(
            username="admin_route_test",
            password_hash=generate_password_hash("RoutePassword123!"),
            full_name="Route Admin",
            role="admin",
            db_path=self.temp_db_path
        )

        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.temp_db_path)
        self.db_patcher.start()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Log in as admin
        with self.client.session_transaction() as sess:
            sess["officer_id"] = self.admin_id
            sess["username"] = "admin_route_test"
            sess["role"] = "admin"

    def tearDown(self):
        self.db_patcher.stop()
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_unauthenticated_access_redirects(self):
        """Test that unauthenticated requests to protected pages redirect to login."""
        unauth_client = self.app.test_client()
        for path in ["/", "/record", "/settings", "/view_telugu/1"]:
            resp = unauth_client.get(path)
            self.assertEqual(resp.status_code, 302, f"Path {path} did not redirect to login")
            self.assertIn("/login", resp.headers["Location"])

    def test_dashboard_route(self):
        """Test GET / returns 200 with dashboard elements."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("AI Police Complaint Drafting System", content)
        self.assertIn("Record Complaint", content)
        self.assertIn("Location Settings", content)
        self.assertIn("Total Cases", content)

    def test_record_route(self):
        """Test GET /record returns 200 with form elements."""
        response = self.client.get("/record")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("Complainant Name", content)
        self.assertIn("Phone Number", content)
        self.assertIn("Start Recording", content)
        self.assertIn("Generate Complaint", content)

    def test_settings_route(self):
        """Test GET /settings returns 200 with station settings form."""
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("Police Station Settings", content)
        self.assertIn("station_name", content)
        self.assertIn("Save Settings", content)

    def test_view_complaints_routes(self):
        """Test GET /view_telugu/<id> and /view_english/<id> for existing complaints."""
        # Test Telugu view
        resp_telugu = self.client.get("/view_telugu/1")
        self.assertEqual(resp_telugu.status_code, 200)
        self.assertIn("Case ID", resp_telugu.data.decode("utf-8"))

        # Test English view
        resp_english = self.client.get("/view_english/1")
        self.assertEqual(resp_english.status_code, 200)
        self.assertIn("Case ID", resp_english.data.decode("utf-8"))

    def test_static_css_assets(self):
        """Test static CSS assets are served correctly."""
        for css in ["common.css", "dashboard.css", "record.css", "settings.css", "complaint.css"]:
            resp = self.client.get(f"/static/css/{css}")
            self.assertEqual(resp.status_code, 200, f"Failed to serve /static/css/{css}")

    def test_static_js_assets(self):
        """Test static JS assets are served correctly."""
        for js in ["dashboard.js", "record.js"]:
            resp = self.client.get(f"/static/js/{js}")
            self.assertEqual(resp.status_code, 200, f"Failed to serve /static/js/{js}")


if __name__ == "__main__":
    unittest.main()
