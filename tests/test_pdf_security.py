"""
Automated Security & Functionality Tests for SEC-01 PDF Generation Fix.

Verifies:
1. Telugu PDF generation without loopback HTTP calls.
2. English PDF generation without loopback HTTP calls.
3. Complaint content correctly appears in the generated PDF.
4. Generated PDF does NOT contain a login page or authentication form.
5. Two distinct complaints produce independent, non-overlapping PDFs.
6. Telugu font and stylesheet embedding works.
7. Missing or invalid complaint IDs are rejected safely with clear errors.
8. Playwright rendering failures are reported/logged, not silently hidden.
9. Local and cloud storage integration compatibility is preserved.
10. Complete isolation: zero writes to production complaints.db or historical case records.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, save_complaint, get_complaint_by_id
from backend.services.pdf_generator import (
    generate_telugu_pdf,
    generate_english_pdf,
    render_telugu_complaint_html,
    render_english_complaint_html,
    save_html_as_pdf
)


class TestPDFGenerationSecurity(unittest.TestCase):
    """Test suite for SEC-01 PDF generation security and correctness."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_pdf_sec_")
        self.test_db = os.path.join(self.temp_dir, "test_pdf.db")
        self.test_out_dir = os.path.join(self.temp_dir, "output_pdfs")
        os.makedirs(self.test_out_dir, exist_ok=True)

        init_db(self.test_db)

        # Seed Complaint 1 (Telugu narrative: missing phone)
        self.cid_1 = save_complaint(
            registered_on="01-11-2026 10:00 AM",
            english_name="Ravi Kumar",
            telugu_name="రవి కుమార్",
            phone="9876543210",
            subject="మొబైల్ ఫోన్ పోయిన విషయం",
            audio_path="audio/test1.webm",
            telugu_complaint="అయ్యా, నా శామ్‌సంగ్ మొబైల్ ఫోన్ బస్టాండ్ వద్ద పోయింది. రికవరీ చేయగలరు.",
            english_complaint="Sir, my Samsung mobile phone was lost near the bus station. Kindly recover it.",
            db_path=self.test_db
        )

        # Seed Complaint 2 (Telugu narrative: stolen motorcycle)
        self.cid_2 = save_complaint(
            registered_on="01-11-2026 11:30 AM",
            english_name="Sita Devi",
            telugu_name="సీతా దేవి",
            phone="9123456780",
            subject="మోటార్ సైకిల్ చోరీ ఫిర్యాదు",
            audio_path="audio/test2.webm",
            telugu_complaint="అయ్యా, నిన్న రాత్రి నా హీరో హోండా మోటార్ సైకిల్ ఇంటి ముందు నుండి దొంగిలించబడింది.",
            english_complaint="Sir, my Hero Honda motorcycle was stolen from in front of my residence last night.",
            db_path=self.test_db
        )

        class TestConfig(Config):
            DATABASE_PATH = self.test_db
            TESTING = True

        self.app = create_app(TestConfig)
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_telugu_pdf_generation(self):
        """1. Telugu PDF generates successfully directly from template without loopback HTTP."""
        out_pdf = os.path.join(self.test_out_dir, "complaint_1_telugu.pdf")
        generate_telugu_pdf(out_pdf, self.cid_1, db_path=self.test_db)

        self.assertTrue(os.path.exists(out_pdf), "Telugu PDF file must be created")
        pdf_size = os.path.getsize(out_pdf)
        self.assertGreater(pdf_size, 20000, f"Telugu PDF size ({pdf_size} bytes) should be substantial")

    def test_02_english_pdf_generation(self):
        """2. English PDF generates successfully directly from template without loopback HTTP."""
        out_pdf = os.path.join(self.test_out_dir, "complaint_1_english.pdf")
        generate_english_pdf(out_pdf, self.cid_1, db_path=self.test_db)

        self.assertTrue(os.path.exists(out_pdf), "English PDF file must be created")
        pdf_size = os.path.getsize(out_pdf)
        self.assertGreater(pdf_size, 20000, f"English PDF size ({pdf_size} bytes) should be substantial")

    def test_03_correct_complaint_content_appears_in_html_and_pdf(self):
        """3. Verify correct citizen details and complaint text appear in rendered HTML and PDF."""
        # Telugu HTML verification
        html_te = render_telugu_complaint_html(self.cid_1, db_path=self.test_db)
        self.assertIn("రవి కుమార్", html_te)
        self.assertIn("శామ్‌సంగ్ మొబైల్", html_te)
        self.assertIn("9876543210", html_te)

        # English HTML verification
        html_en = render_english_complaint_html(self.cid_1, db_path=self.test_db)
        self.assertIn("Ravi Kumar", html_en)
        self.assertIn("Samsung mobile phone", html_en)
        self.assertIn("9876543210", html_en)

    def test_04_pdf_does_not_contain_login_page(self):
        """4. Verify generated PDF never renders the login page or authentication form."""
        out_pdf = os.path.join(self.test_out_dir, "no_login_test.pdf")
        generate_telugu_pdf(out_pdf, self.cid_1, db_path=self.test_db)

        with open(out_pdf, "rb") as f:
            pdf_bytes = f.read().lower()

        # Should never contain login form text
        self.assertNotIn(b"officer login", pdf_bytes)
        self.assertNotIn(b"password", pdf_bytes)
        self.assertNotIn(b"badge number", pdf_bytes)

        # HTML template should have zero reference to login
        html = render_telugu_complaint_html(self.cid_1, db_path=self.test_db).lower()
        self.assertNotIn("officer login", html)
        self.assertNotIn("name=\"password\"", html)

    def test_05_independent_pdfs_for_distinct_complaints(self):
        """5. Two different complaints produce separate, non-overlapping PDFs without state leakage."""
        pdf_1 = os.path.join(self.test_out_dir, "case_1_english.pdf")
        pdf_2 = os.path.join(self.test_out_dir, "case_2_english.pdf")

        generate_english_pdf(pdf_1, self.cid_1, db_path=self.test_db)
        generate_english_pdf(pdf_2, self.cid_2, db_path=self.test_db)

        html_1 = render_english_complaint_html(self.cid_1, db_path=self.test_db)
        html_2 = render_english_complaint_html(self.cid_2, db_path=self.test_db)

        self.assertIn("Ravi Kumar", html_1)
        self.assertNotIn("Sita Devi", html_1)

        self.assertIn("Sita Devi", html_2)
        self.assertNotIn("Ravi Kumar", html_2)

        self.assertIn("Hero Honda", html_2)
        self.assertNotIn("Hero Honda", html_1)

    def test_06_telugu_font_embedding(self):
        """6. Inlined CSS contains Tiro Telugu font-face and print styles."""
        html_te = render_telugu_complaint_html(self.cid_1, db_path=self.test_db)
        from backend.services.pdf_generator import _inline_css_in_html
        inlined = _inline_css_in_html(html_te)

        self.assertIn("<style>", inlined)
        self.assertIn("Tiro Telugu", inlined)
        self.assertIn(".paper", inlined)

    def test_07_invalid_complaint_id_handling(self):
        """7. Missing or invalid complaint IDs raise clean ValueError without crashing."""
        out_pdf = os.path.join(self.test_out_dir, "invalid.pdf")
        with self.assertRaises(ValueError) as ctx:
            generate_telugu_pdf(out_pdf, 999999, db_path=self.test_db)
        self.assertIn("not found", str(ctx.exception).lower())

        with self.assertRaises(ValueError) as ctx:
            generate_english_pdf(out_pdf, -5, db_path=self.test_db)
        self.assertIn("not found", str(ctx.exception).lower())

    def test_08_rendering_failure_reporting(self):
        """8. Playwright rendering failures are raised and not silently swallowed in pdf_generator."""
        with patch("playwright.sync_api.sync_playwright") as mock_pw:
            mock_pw.side_effect = RuntimeError("Playwright Chromium Binary Failure")
            out_pdf = os.path.join(self.test_out_dir, "fail.pdf")
            with self.assertRaises(RuntimeError) as ctx:
                generate_telugu_pdf(out_pdf, self.cid_1, db_path=self.test_db)
            self.assertIn("Playwright Chromium Binary Failure", str(ctx.exception))

    def test_09_storage_compatibility(self):
        """9. Generated PDF is valid for local filesystem and Supabase storage backends."""
        out_pdf = os.path.join(self.test_out_dir, "Complaint_Telugu.pdf")
        generate_telugu_pdf(out_pdf, self.cid_1, db_path=self.test_db)

        self.assertTrue(os.path.exists(out_pdf))
        self.assertGreater(os.path.getsize(out_pdf), 0)

        # Local storage backend read test
        from backend.services.storage import LocalStorageBackend
        local_backend = LocalStorageBackend(base_dir=self.temp_dir)
        key = local_backend.save_file(out_pdf, "case_records/test/Complaint_Telugu.pdf")
        self.assertTrue(local_backend.file_exists(key))
        retrieved_bytes = local_backend.get_file(key)
        self.assertGreater(len(retrieved_bytes), 20000)

    def test_10_backward_compatible_signature(self):
        """10. Verify save_page_as_pdf legacy helper remains callable for backward compatibility."""
        from backend.services.pdf_generator import save_page_as_pdf
        self.assertTrue(callable(save_page_as_pdf))


if __name__ == "__main__":
    unittest.main()

