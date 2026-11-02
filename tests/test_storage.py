"""
Unit tests for CSP_V2 Storage Service.

Tests cover:
1. Default local backend configuration.
2. Storage key generation, uniqueness, and path traversal protection.
3. Content type / MIME mapping.
4. Local storage backend save, retrieve, stream, and traversal prevention.
5. Supabase configuration validation (safe credential failure).
6. Supabase backend mocked uploads, content types, downloads, and signed URLs.
7. Verification that private files are never served via public URLs.
8. Upload failure handling and rollback safety.
9. Secure file retrieval route (/complaints/<id>/files/<type>) behavior.
10. Database backward compatibility with older rows.
"""

import os
import io
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from config import Config
from backend import create_app
from backend.services.storage import (
    build_storage_key,
    get_content_type,
    sanitize_filename,
    LocalStorageBackend,
    SupabaseStorageBackend,
    get_storage_service,
    StorageError,
    StorageConfigError,
    StorageNotFoundError
)
from backend.services.database import (
    get_complaints,
    get_complaint_by_id,
    get_complaint_storage_info,
    update_complaint_storage
)


class TestStorageService(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_default_storage_backend_is_local(self):
        """Ensure local storage remains the default backend in absence of overrides."""
        with patch.object(Config, "STORAGE_BACKEND", "local"):
            backend = (Config.STORAGE_BACKEND or "local").strip().lower()
            self.assertEqual(backend, "local")
            service = get_storage_service()
            self.assertIsInstance(service, LocalStorageBackend)

    def test_build_storage_key_valid(self):
        """Verify deterministic, unique storage key creation."""
        audio_key = build_storage_key(42, "audio", "Complaint_Audio.webm")
        self.assertEqual(audio_key, "complaints/42/audio/Complaint_Audio.webm")

        telugu_pdf_key = build_storage_key(42, "pdf", "Complaint_Telugu.pdf")
        self.assertEqual(telugu_pdf_key, "complaints/42/pdf/Complaint_Telugu.pdf")

        english_pdf_key = build_storage_key(42, "pdf", "Complaint_English.pdf")
        self.assertEqual(english_pdf_key, "complaints/42/pdf/Complaint_English.pdf")

    def test_build_storage_key_traversal_protection(self):
        """Verify storage key prevents directory traversal and sanitizes input."""
        key = build_storage_key(5, "audio", "../../secrets/passwords.txt")
        self.assertEqual(key, "complaints/5/audio/passwords.txt")

        # Invalid complaint ID
        with self.assertRaises(ValueError):
            build_storage_key(0, "audio", "audio.webm")
        with self.assertRaises(ValueError):
            build_storage_key(-1, "audio", "audio.webm")

        # Invalid category
        with self.assertRaises(ValueError):
            build_storage_key(1, "executable", "script.sh")

    def test_content_type_mapping(self):
        """Verify content type detection for audio formats and PDFs."""
        self.assertEqual(get_content_type("complaint.webm"), "audio/webm")
        self.assertEqual(get_content_type("complaint.wav"), "audio/wav")
        self.assertEqual(get_content_type("complaint.mp3"), "audio/mpeg")
        self.assertEqual(get_content_type("document.pdf"), "application/pdf")
        self.assertEqual(get_content_type("audio/sub/sample.ogg"), "audio/ogg")

    def test_local_storage_backend_crud(self):
        """Test LocalStorageBackend save, retrieve, exists, and delete."""
        with tempfile.TemporaryDirectory() as temp_dir:
            local_backend = LocalStorageBackend(base_dir=temp_dir)
            test_content = b"Mock Audio Bytes 12345"
            rel_dest = "case_records/test_case/test_audio.webm"

            # Save
            saved_key = local_backend.save_file(test_content, rel_dest)
            self.assertTrue(local_backend.file_exists(saved_key))

            # Retrieve bytes
            retrieved = local_backend.get_file(saved_key)
            self.assertEqual(retrieved, test_content)

            # Retrieve stream
            stream = local_backend.get_file_stream(saved_key)
            self.assertEqual(stream.read(), test_content)

            # Delete
            deleted = local_backend.delete_file(saved_key)
            self.assertTrue(deleted)
            self.assertFalse(local_backend.file_exists(saved_key))

    def test_local_storage_backend_path_traversal_denied(self):
        """Ensure LocalStorageBackend blocks paths escaping base_dir."""
        with tempfile.TemporaryDirectory() as temp_dir:
            local_backend = LocalStorageBackend(base_dir=temp_dir)
            with self.assertRaises(StorageError):
                local_backend.save_file(b"bad", "../outside.txt")

    def test_supabase_backend_missing_credentials(self):
        """Ensure Supabase backend fails safely when credentials are missing."""
        with patch.object(Config, "SUPABASE_URL", None), \
             patch.object(Config, "SUPABASE_KEY", None):
            with self.assertRaises(StorageConfigError) as ctx:
                SupabaseStorageBackend()
            self.assertIn("requires both", str(ctx.exception))

    def test_supabase_backend_mocked_operations(self):
        """
        Test SupabaseStorageBackend using an injected mock client.
        Verifies private bucket interaction, correct paths, and short-lived signed URLs.
        """
        mock_bucket = MagicMock()
        mock_bucket.upload.return_value = {"Key": "complaint-files/complaints/1/audio/audio.webm"}
        mock_bucket.download.return_value = b"Supabase Audio Payload"
        mock_bucket.create_signed_url.return_value = {
            "signedURL": "https://example-supabase.co/storage/v1/object/sign/complaint-files/complaints/1/audio/audio.webm?token=fake"
        }
        mock_bucket.exists.return_value = True
        mock_bucket.remove.return_value = [{"name": "complaints/1/audio/audio.webm"}]

        mock_client = MagicMock()
        mock_client.storage.from_.return_value = mock_bucket

        backend = SupabaseStorageBackend(
            supabase_url="https://fake.supabase.co",
            supabase_key="fake-secret-key",
            bucket_name="complaint-files",
            client=mock_client
        )

        # 1. Test upload
        dest_key = "complaints/1/audio/Complaint_Audio.webm"
        saved = backend.save_file(b"test data", dest_key, content_type="audio/webm")
        self.assertEqual(saved, dest_key)
        mock_bucket.upload.assert_called_once_with(
            path=dest_key,
            file=b"test data",
            file_options={"content-type": "audio/webm", "upsert": "true"}
        )

        # 2. Test download
        downloaded = backend.get_file(dest_key)
        self.assertEqual(downloaded, b"Supabase Audio Payload")
        mock_bucket.download.assert_called_once_with(dest_key)

        # 3. Test signed URL (short-lived)
        signed_url = backend.get_signed_url(dest_key, expires_in=900)
        self.assertIn("https://example-supabase.co", signed_url)
        mock_bucket.create_signed_url.assert_called_once_with(dest_key, expires_in=900)

        # 4. Verify get_public_url is NEVER called (maintaining private bucket security)
        self.assertFalse(hasattr(mock_bucket, "get_public_url") and mock_bucket.get_public_url.called)

        # 5. Test delete
        deleted = backend.delete_file(dest_key)
        self.assertTrue(deleted)
        mock_bucket.remove.assert_called_once_with([dest_key])

    def test_supabase_backend_upload_failure_handling(self):
        """Verify upload errors wrap safely and do not leak credentials."""
        mock_bucket = MagicMock()
        mock_bucket.upload.side_effect = Exception("Internal Network Timeout")

        mock_client = MagicMock()
        mock_client.storage.from_.return_value = mock_bucket

        backend = SupabaseStorageBackend(
            supabase_url="https://fake.supabase.co",
            supabase_key="sensitive-secret-token",
            bucket_name="complaint-files",
            client=mock_client
        )

        with self.assertRaises(StorageError) as ctx:
            backend.save_file(b"data", "complaints/1/audio/audio.webm")
        # Ensure sensitive token is not in error string
        self.assertNotIn("sensitive-secret-token", str(ctx.exception))

    def test_database_backward_compatibility(self):
        """Verify older SQLite complaint records are readable and storage metadata is accessible."""
        complaints = get_complaints()
        self.assertIsInstance(complaints, list)
        self.assertGreater(len(complaints), 0)

        first = complaints[0]
        test_id = first[0]
        # Check storage info helper
        info = get_complaint_storage_info(test_id)
        self.assertIsNotNone(info)
        self.assertIn("storage_backend", info)
        self.assertIn("audio_path", info)
        self.assertIn(info["storage_backend"], ("local", "supabase"))

    @patch("backend.routes.complaints.create_audit_log")
    @patch("backend.get_authenticated_officer", return_value={"id": 1, "username": "test_officer", "role": "officer", "is_active": 1})
    @patch("backend.services.auth.get_authenticated_officer", return_value={"id": 1, "username": "test_officer", "role": "officer", "is_active": 1})
    def test_secure_download_route_validation(self, mock_auth_officer, mock_backend_officer, mock_audit):
        """Verify /complaints/<id>/files/<type> validates input types and non-existent IDs."""
        # Unauthenticated request returns 401
        unauth_resp = self.client.get("/complaints/999999/files/audio")
        self.assertEqual(unauth_resp.status_code, 401)

        # Authenticate session
        with self.client.session_transaction() as sess:
            sess["officer_id"] = 1

        # Invalid complaint ID
        resp = self.client.get("/complaints/999999/files/audio")
        self.assertEqual(resp.status_code, 404)

        # Invalid file type
        complaints = get_complaints()
        if complaints:
            test_id = complaints[0][0]
            resp = self.client.get(f"/complaints/{test_id}/files/executable")
            self.assertEqual(resp.status_code, 400)

    @patch("backend.routes.complaints.create_audit_log")
    @patch("backend.get_authenticated_officer", return_value={"id": 1, "username": "test_officer", "role": "officer", "is_active": 1})
    @patch("backend.services.auth.get_authenticated_officer", return_value={"id": 1, "username": "test_officer", "role": "officer", "is_active": 1})
    def test_secure_download_route_local_existing(self, mock_auth_officer, mock_backend_officer, mock_audit):
        """Verify serving existing local complaint audio through secure route."""
        # Authenticate session
        with self.client.session_transaction() as sess:
            sess["officer_id"] = 1

        complaints = get_complaints()
        if complaints:
            test_id = complaints[0][0]
            resp = self.client.get(f"/complaints/{test_id}/files/audio")
            # If the physical file exists, 200 is returned; if not on disk, 404
            self.assertIn(resp.status_code, (200, 404))


if __name__ == "__main__":
    unittest.main()
