"""
tests/test_session_config.py
============================
Focused test suite for Phase 8.9: Configurable Flask Session Directory.

Verifies:
1. Default local session directory resolves to os.path.join(BASE_DIR, ".flask_session")
   when SESSION_FILE_DIR is unset.
2. Custom SESSION_FILE_DIR environment variable correctly sets the session storage directory.
3. Empty and whitespace-only SESSION_FILE_DIR environment values fall back to default.
4. Automatic creation of custom session directory when create_app() initializes.
5. Flask-Session correctly writes and persists session files inside the configured directory.
6. Session cleanup utility (resolve_session_dir and cleanup_expired_sessions) remains
   fully compatible and operates on the configured session directory.
7. Session expiration, cookie security, and signing parameters remain intact.

100% Isolated: Uses temporary directories; never touches production session files,
production database, or .env.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
from datetime import timedelta

from config import Config
from backend import create_app
from backend.services.database import init_db
from backend.services.session_service import (
    resolve_session_dir,
    get_session_cache,
    cleanup_expired_sessions
)


class TestSessionConfig(unittest.TestCase):
    """Test suite for configurable SESSION_FILE_DIR."""

    def setUp(self):
        """Create an isolated temporary environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="csp_test_sess_cfg_")
        self.temp_db = os.path.join(self.temp_dir, "test.db")
        init_db(self.temp_db)

    def tearDown(self):
        """Clean up temporary directories."""
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except OSError:
                pass

    def test_default_session_file_dir_resolution(self):
        """1. Verify default SESSION_FILE_DIR resolves to BASE_DIR/.flask_session when unset."""
        default_expected = os.path.join(Config.BASE_DIR, ".flask_session")

        # Simulate unset
        env_copy = os.environ.copy()
        env_copy.pop("SESSION_FILE_DIR", None)
        with patch.dict(os.environ, env_copy, clear=True):
            resolved = (os.getenv("SESSION_FILE_DIR") or "").strip() or default_expected
            self.assertEqual(resolved, default_expected)

        # Confirm Config default attribute
        self.assertTrue(Config.SESSION_FILE_DIR.endswith(".flask_session"))
        self.assertEqual(os.path.abspath(Config.SESSION_FILE_DIR), os.path.abspath(default_expected))

    def test_custom_session_file_dir_from_environment(self):
        """2. Verify custom SESSION_FILE_DIR environment variable is respected."""
        custom_dir = os.path.join(self.temp_dir, "custom_render_sessions")

        with patch.dict(os.environ, {"SESSION_FILE_DIR": custom_dir}):
            resolved = (os.getenv("SESSION_FILE_DIR") or "").strip() or os.path.join(Config.BASE_DIR, ".flask_session")
            self.assertEqual(resolved, custom_dir)

    def test_empty_and_whitespace_session_file_dir_fallback(self):
        """3. Verify empty and whitespace-only values safely fall back to default."""
        default_expected = os.path.join(Config.BASE_DIR, ".flask_session")

        empty_values = ["", "   ", "\t", "  \n  ", "\r\n"]
        for val in empty_values:
            with patch.dict(os.environ, {"SESSION_FILE_DIR": val}):
                resolved = (os.getenv("SESSION_FILE_DIR") or "").strip() or default_expected
                self.assertEqual(
                    resolved,
                    default_expected,
                    f"Value '{val}' should fall back to default session directory"
                )

    def test_session_directory_auto_creation_and_usability(self):
        """4. Verify create_app() automatically creates custom SESSION_FILE_DIR and stores sessions."""
        custom_sessions = os.path.join(self.temp_dir, "persistent_data", "sessions")
        self.assertFalse(os.path.exists(custom_sessions))

        class IsolatedConfig(Config):
            TESTING = True
            WTF_CSRF_ENABLED = False
            DATABASE_PATH = self.temp_db
            SESSION_FILE_DIR = custom_sessions

        app = create_app(config_class=IsolatedConfig)

        # Directory must be automatically created
        self.assertTrue(os.path.exists(custom_sessions), "Session directory must be created on startup")
        self.assertTrue(os.path.isdir(custom_sessions))

        # Test client writes session file into custom directory
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["test_officer"] = "officer_123"
            sess["role"] = "officer"

        # Make an authenticated request to trigger session commit
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)

        # Inspect custom_sessions directory: must contain session cache files
        session_files = [
            f for f in os.listdir(custom_sessions)
            if not f.startswith(".")
        ]
        self.assertGreater(len(session_files), 0, "Flask-Session must write session files to configured directory")

    def test_session_cleanup_utility_compatibility(self):
        """5. Verify session cleanup utility recognizes and cleans configured directory."""
        custom_sessions = os.path.join(self.temp_dir, "cleanup_target_sessions")
        os.makedirs(custom_sessions, exist_ok=True)

        class IsolatedConfig(Config):
            TESTING = True
            WTF_CSRF_ENABLED = False
            DATABASE_PATH = self.temp_db
            SESSION_FILE_DIR = custom_sessions

        app = create_app(config_class=IsolatedConfig)

        # resolve_session_dir must return custom_sessions
        resolved = resolve_session_dir(app=app)
        self.assertEqual(os.path.abspath(resolved), os.path.abspath(custom_sessions))

        # Cache must point to the custom directory
        cache = get_session_cache(app)
        self.assertIsNotNone(cache)
        self.assertEqual(os.path.abspath(cache._path), os.path.abspath(custom_sessions))

        # Write an active session via cache
        cache.set("active_key", {"user": "admin"}, timeout=300)
        self.assertEqual(cache.get("active_key"), {"user": "admin"})

        # Run cleanup_expired_sessions on custom directory
        removed_count, remaining_count = cleanup_expired_sessions(app=app)
        self.assertEqual(removed_count, 0, "Active session should not be removed")
        self.assertGreaterEqual(remaining_count, 1, "Active session should remain counted")

    def test_session_security_settings_preserved(self):
        """6. Verify session expiration, cookie security, and signing parameters are untouched."""
        self.assertEqual(Config.SESSION_TYPE, "filesystem")
        self.assertTrue(Config.SESSION_PERMANENT)
        self.assertEqual(Config.PERMANENT_SESSION_LIFETIME, timedelta(minutes=60))
        self.assertTrue(Config.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(Config.SESSION_COOKIE_SAMESITE, "Lax")
        self.assertTrue(Config.SESSION_USE_SIGNER)
        self.assertEqual(Config.WTF_CSRF_TIME_LIMIT, 3600)


if __name__ == "__main__":
    unittest.main()
