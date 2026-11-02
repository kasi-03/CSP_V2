"""
tests/test_storage_migrator.py
==============================
Unit and integration tests for Phase 8.5 - Historical Data Migration Utility.

Verifies:
1. File hash calculation (SHA-256) matches known digests.
2. Physical file location resolution across recorded paths and case_records/ trees.
3. Preservation of exact audio extensions (.wav vs .webm).
4. Manifest generation with proper destination keys and payload calculations.
5. Handling of missing PDFs (complaints 18 & 19) as NULL with MISSING_IGNORED status.
6. Handling of NULL database columns for existing physical PDFs without data loss.
7. Supabase collision detection and protection of complaint 23 object.
8. Dry-run execution generates projected SQL and manifest without mutating database.

100% Isolated: Uses temporary directories, temporary SQLite databases, and mock files only.
Prohibits modifications to production complaints.db, sessions, .env, or cloud objects.
"""

import os
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config import Config
from backend.services.database import init_db, save_complaint
from backend.services.storage_migrator import (
    compute_file_sha256,
    resolve_file_location,
    inspect_supabase_existing_keys,
    generate_migration_manifest,
    execute_dry_run
)


class TestStorageMigrator(unittest.TestCase):
    """Test suite for the safe historical complaint data migration tool."""

    def setUp(self):
        """Set up an isolated temporary workspace with mock complaints and files."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_migration.db")
        self.case_records_dir = os.path.join(self.temp_dir, "case_records")
        self.audio_dir = os.path.join(self.temp_dir, "audio")
        self.generated_dir = os.path.join(self.temp_dir, "generated")

        os.makedirs(self.case_records_dir, exist_ok=True)
        os.makedirs(self.audio_dir, exist_ok=True)
        os.makedirs(self.generated_dir, exist_ok=True)

        # Initialize temporary database
        init_db(self.db_path)

        # Create 3 test complaints:
        # Case 1: Complete case with .wav audio, existing PDFs in case folder
        # Case 2: Complete case with .webm audio, NULL PDF columns in DB, but PDFs exist on disk
        # Case 3: Incomplete case (like 18 & 19) with .webm audio, missing PDFs
        self._populate_test_cases()

    def tearDown(self):
        """Clean up temporary test directory."""
        import shutil
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass

    def _populate_test_cases(self):
        """Create mock files and database records matching the real structure."""
        # Case 1: C001
        c1_folder = Path(self.case_records_dir) / "2026" / "June" / "C001_Test_User_29-06-2026"
        c1_folder.mkdir(parents=True, exist_ok=True)
        self.c1_audio = c1_folder / "Complaint_Audio.wav"
        self.c1_audio.write_bytes(b"RIFF_MOCK_WAV_AUDIO_BYTES_FOR_COMPLAINT_1")
        self.c1_telugu = c1_folder / "Complaint_Telugu.pdf"
        self.c1_telugu.write_bytes(b"%PDF-1.4 Mock Telugu PDF Content 1")
        self.c1_english = c1_folder / "Complaint_English.pdf"
        self.c1_english.write_bytes(b"%PDF-1.4 Mock English PDF Content 1")

        cid1 = save_complaint(
            registered_on="29-06-2026 07:27 PM",
            english_name="Test User 1",
            telugu_name="యూజర్ 1",
            phone="9000000001",
            subject="Test Case 1",
            audio_path="audio/test1.webm", # recorded path differs from case folder (legacy)
            telugu_complaint="ఫిర్యాదు 1",
            english_complaint="Complaint 1",
            db_path=self.db_path
        )

        # Case 2: C002 (NULL in DB columns for PDFs, but PDFs physically exist on disk)
        c2_folder = Path(self.case_records_dir) / "2026" / "July" / "C002_Test_User_01-07-2026"
        c2_folder.mkdir(parents=True, exist_ok=True)
        self.c2_audio = c2_folder / "Complaint_Audio.webm"
        self.c2_audio.write_bytes(b"MOCK_WEBM_AUDIO_BYTES_FOR_COMPLAINT_2")
        self.c2_telugu = c2_folder / "Complaint_Telugu.pdf"
        self.c2_telugu.write_bytes(b"%PDF-1.4 Mock Telugu PDF Content 2")
        self.c2_english = c2_folder / "Complaint_English.pdf"
        self.c2_english.write_bytes(b"%PDF-1.4 Mock English PDF Content 2")

        cid2 = save_complaint(
            registered_on="01-07-2026 08:00 PM",
            english_name="Test User 2",
            telugu_name="యూజర్ 2",
            phone="9000000002",
            subject="Test Case 2",
            audio_path=str(self.c2_audio),
            telugu_complaint="ఫిర్యాదు 2",
            english_complaint="Complaint 2",
            db_path=self.db_path
        )

        # Case 3: C003 (Missing PDFs, like complaints 18 & 19)
        c3_folder = Path(self.case_records_dir) / "2026" / "October" / "C003_Test_User_23-10-2026"
        c3_folder.mkdir(parents=True, exist_ok=True)
        self.c3_audio = c3_folder / "Complaint_Audio.webm"
        self.c3_audio.write_bytes(b"MOCK_WEBM_AUDIO_BYTES_FOR_COMPLAINT_3")
        # No PDFs created for C003

        cid3 = save_complaint(
            registered_on="23-10-2026 01:22 PM",
            english_name="Test User 3",
            telugu_name="యూజర్ 3",
            phone="9000000003",
            subject="Test Case 3",
            audio_path=f"C:/mock/windows/path/{self.c3_audio.name}",
            telugu_complaint="ఫిర్యాదు 3",
            english_complaint="Complaint 3",
            db_path=self.db_path
        )

    def test_compute_file_sha256(self):
        """Verify SHA-256 calculation matches expected digest."""
        test_file = os.path.join(self.temp_dir, "test_hash.txt")
        content = b"CSP_V2_MIGRATION_INTEGRITY_CHECK"
        with open(test_file, "wb") as f:
            f.write(content)

        import hashlib
        expected_digest = hashlib.sha256(content).hexdigest()
        self.assertEqual(compute_file_sha256(test_file), expected_digest)

    def test_resolve_file_location(self):
        """Verify resolve_file_location finds files across case_records and direct paths."""
        base_dir = Path(self.temp_dir)

        # Case 1: Audio file with .wav extension resolved from case folder
        resolved_audio = resolve_file_location(1, "audio", "audio/test1.webm", base_dir)
        self.assertIsNotNone(resolved_audio)
        self.assertTrue(resolved_audio.exists())
        self.assertEqual(resolved_audio.suffix.lower(), ".wav")

        # Case 2: Telugu PDF resolved despite being NULL in database
        resolved_telugu = resolve_file_location(2, "telugu_pdf", None, base_dir)
        self.assertIsNotNone(resolved_telugu)
        self.assertTrue(resolved_telugu.exists())
        self.assertEqual(resolved_telugu.name, "Complaint_Telugu.pdf")

        # Case 3: Missing PDFs return None
        missing_telugu = resolve_file_location(3, "telugu_pdf", None, base_dir)
        self.assertIsNone(missing_telugu)
        missing_english = resolve_file_location(3, "english_pdf", None, base_dir)
        self.assertIsNone(missing_english)

    def test_generate_migration_manifest(self):
        """Verify generate_migration_manifest builds valid manifest with hashes and keys."""
        manifest = generate_migration_manifest(
            db_path=self.db_path,
            base_dir=Path(self.temp_dir),
            check_supabase=False
        )

        self.assertEqual(manifest["total_complaints"], 3)
        # Case 1: 3 files (audio, tel, eng)
        # Case 2: 3 files (audio, tel, eng)
        # Case 3: 1 file (audio only)
        # Total files = 7
        self.assertEqual(manifest["total_files_available"], 7)
        self.assertEqual(manifest["missing_file_references"], 2) # Case 3's two PDFs

        c1 = manifest["complaints"][0]
        self.assertEqual(c1["complaint_id"], 1)
        # Preserves .wav extension
        self.assertEqual(c1["files"]["audio"]["destination_key"], "complaints/1/audio/Complaint_Audio.wav")
        self.assertEqual(c1["files"]["telugu_pdf"]["destination_key"], "complaints/1/pdf/Complaint_Telugu.pdf")
        self.assertEqual(c1["files"]["english_pdf"]["destination_key"], "complaints/1/pdf/Complaint_English.pdf")
        self.assertEqual(c1["files"]["audio"]["status"], "READY")
        self.assertIsNotNone(c1["files"]["audio"]["sha256"])

        # Case 3 has missing PDFs marked as MISSING_IGNORED with None destination keys
        c3 = manifest["complaints"][2]
        self.assertEqual(c3["complaint_id"], 3)
        self.assertEqual(c3["files"]["audio"]["status"], "READY")
        self.assertEqual(c3["files"]["audio"]["destination_key"], "complaints/3/audio/Complaint_Audio.webm")
        self.assertEqual(c3["files"]["telugu_pdf"]["status"], "MISSING_IGNORED")
        self.assertIsNone(c3["files"]["telugu_pdf"]["destination_key"])
        self.assertIsNone(c3["proposed_db_update"]["telugu_pdf_path"])
        self.assertIsNone(c3["proposed_db_update"]["english_pdf_path"])

    def test_supabase_collision_detection_and_protection(self):
        """Verify collision detection flags existing keys and protects complaint 23."""
        mock_summary = {
            "connected": True,
            "bucket": "complaint-files",
            "existing_keys_count": 2,
            "protected_objects": ["complaints/23/audio/Complaint_Audio.webm"],
            "error": None
        }
        mock_existing = [
            "complaints/1/audio/Complaint_Audio.wav", # Collides with Complaint 1
            "complaints/23/audio/Complaint_Audio.webm" # Protected object
        ]

        with patch("backend.services.storage_migrator.inspect_supabase_existing_keys", return_value=(mock_summary, mock_existing)):
            manifest = generate_migration_manifest(
                db_path=self.db_path,
                base_dir=Path(self.temp_dir),
                check_supabase=True
            )

            # Complaint 1 audio should be flagged as COLLISION
            c1_audio = manifest["complaints"][0]["files"]["audio"]
            self.assertEqual(c1_audio["status"], "COLLISION")

            # Verify complaint 23 is listed as protected object
            self.assertIn("complaints/23/audio/Complaint_Audio.webm", manifest["supabase_verification"]["protected_objects"])
            self.assertIn("complaints/1/audio/Complaint_Audio.wav", manifest["supabase_verification"]["collisions_detected"])

    def test_dry_run_preserves_database_and_files(self):
        """Verify execute_dry_run performs a zero-mutation simulation."""
        manifest_out = os.path.join(self.temp_dir, "test_manifest.json")

        manifest = execute_dry_run(
            db_path=self.db_path,
            output_manifest_path=manifest_out,
            check_supabase=False,
            base_dir=Path(self.temp_dir)
        )

        self.assertTrue(os.path.exists(manifest_out))
        with open(manifest_out, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data["total_complaints"], 3)
        self.assertEqual(saved_data["total_files_available"], 7)
        self.assertEqual(saved_data["missing_file_references"], 2)

        # Strictly verify database was NOT mutated
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT storage_backend FROM complaints")
        backends = [row[0] for row in cursor.fetchall()]
        conn.close()

        # All rows must remain 'local' (unchanged)
        for b in backends:
            self.assertEqual(b, "local")


if __name__ == "__main__":
    unittest.main()
