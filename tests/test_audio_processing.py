"""
Tests for audio processing service and /process route without FFmpeg.
Verifies direct Groq Whisper transcription for WebM and WAV, format validation,
empty file handling, and complaint processing with full database and storage isolation.
"""

import os
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, create_officer
from backend.services.auth import generate_password_hash
from backend.services.speech import speech_to_text


class TestAudioProcessing(unittest.TestCase):

    def setUp(self):
        """Set up isolated test database, test client, and tracking for cleanup."""
        # Create an isolated temporary database for this test suite
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        # Initialize schema in temporary database
        init_db(self.temp_db_path)

        # Patch Config.DATABASE_PATH to use isolated temporary database
        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.temp_db_path)
        self.db_patcher.start()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Seed an authenticated officer in the isolated test database
        self.officer_id = create_officer(
            username="audio_officer",
            password_hash=generate_password_hash("TestPassword123!"),
            full_name="Audio Test Officer",
            badge_number="999",
            role="officer",
            db_path=self.temp_db_path
        )
        with self.client.session_transaction() as sess:
            sess["officer_id"] = self.officer_id
            sess["username"] = "audio_officer"
            sess["role"] = "officer"

        self.created_dirs = []
        self.created_files = []

    def _get_csrf_token(self, endpoint="/record") -> str:
        """Helper to fetch an active CSRF token from a form page."""
        resp = self.client.get(endpoint)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', resp.data.decode("utf-8"))
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', resp.data.decode("utf-8"))
        return match.group(1) if match else ""

    def tearDown(self):
        """Clean up all isolated temporary database and filesystem artifacts."""
        self.db_patcher.stop()

        # Remove temporary SQLite database
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

        # Clean up any test-created case folders
        for d in self.created_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)

        for f in self.created_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

        # Clean up any test case folders generated in case_records
        for p in Path(Config.CASE_RECORDS_FOLDER).glob("**/*Test_User*"):
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)

        for p in Path(Config.CASE_RECORDS_FOLDER).glob("**/*Kasi_Rao*01-11-2026*"):
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)

    def test_accepted_webm_transcription(self):
        """Verify WebM format transcribes directly using Groq Whisper without FFmpeg."""
        sample_webm = os.path.join("audio", "Complaint_Audio.webm")
        if not os.path.exists(sample_webm):
            self.skipTest("Sample Complaint_Audio.webm not found")

        text = speech_to_text(sample_webm)
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 10, "Transcribed text should not be empty")

    def test_accepted_wav_transcription(self):
        """Verify WAV format transcribes directly using Groq Whisper without FFmpeg."""
        sample_wav = os.path.join("audio", "missing_phone.wav")
        if not os.path.exists(sample_wav):
            self.skipTest("Sample missing_phone.wav not found")

        text = speech_to_text(sample_wav)
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 10, "Transcribed text should not be empty")

    def test_unsupported_audio_format(self):
        """Verify that unsupported audio extensions raise ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False) as f:
            f.write(b"fake audio data")
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                speech_to_text(temp_path)
            self.assertIn("Unsupported audio format", str(ctx.exception))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_empty_audio_file(self):
        """Verify that a 0-byte audio file raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as f:
            temp_path = f.name  # 0 bytes

        try:
            with self.assertRaises(ValueError) as ctx:
                speech_to_text(temp_path)
            self.assertIn("empty", str(ctx.exception).lower())
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_nonexistent_audio_file(self):
        """Verify that a non-existent file path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            speech_to_text("non_existent_audio_file.webm")

    def test_process_route_empty_audio_submission(self):
        """Verify submitting /process without audio returns error message."""
        csrf_token = self._get_csrf_token("/record")
        data = {
            "csrf_token": csrf_token,
            "complainant_name": "Test Citizen",
            "phone_number": "9000000000"
        }
        response = self.client.post("/process", data=data)
        self.assertEqual(response.status_code, 200)
        content = response.data.decode("utf-8")
        self.assertIn("No audio file was received", content)

    def test_process_route_with_webm_upload(self):
        """
        Verify end-to-end complaint generation when uploading Complaint_Audio.webm.
        Mocks external AI, speech, and cloud storage to ensure full isolation and
        guarantee zero writes to production complaints.db or Supabase bucket.
        """
        sample_webm = os.path.join("audio", "Complaint_Audio.webm")
        if not os.path.exists(sample_webm):
            self.skipTest("Sample Complaint_Audio.webm not found")

        with open(sample_webm, "rb") as f:
            audio_bytes = f.read()

        csrf_token = self._get_csrf_token("/record")
        # Track destination file in audio/ for cleanup
        uploaded_audio_copy = os.path.join(Config.UPLOAD_FOLDER, "test_synthetic_audio.webm")
        self.created_files.append(uploaded_audio_copy)

        data = {
            "csrf_token": csrf_token,
            "complainant_name": "Test User",
            "phone_number": "9876543210",
            "audio": (io.BytesIO(audio_bytes), "test_synthetic_audio.webm")
        }

        with patch("backend.routes.complaints.speech_to_text", return_value="టెస్ట్ ఆడియో వివరణ"), \
             patch("backend.routes.complaints.clean_speech", return_value="టెస్ట్ ఆడియో వివరణ"), \
             patch("backend.routes.complaints.generate_complaint", return_value="ఇది పరీక్ష ఫిర్యాదు."), \
             patch("backend.routes.complaints.translate_to_english", return_value="This is a test complaint."), \
             patch("backend.routes.complaints.generate_subject", return_value="Test Subject"), \
             patch("backend.routes.complaints.generate_telugu_pdf"), \
             patch("backend.routes.complaints.generate_english_pdf"), \
             patch.object(Config, "STORAGE_BACKEND", "local"):
            response = self.client.post(
                "/process",
                data=data,
                content_type="multipart/form-data"
            )
            self.assertEqual(response.status_code, 200)
            content = response.data.decode("utf-8")
            self.assertIn("Case ID", content)
            self.assertIn("Download Telugu PDF", content)


if __name__ == "__main__":
    unittest.main()
