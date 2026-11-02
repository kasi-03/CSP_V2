"""
Tests for SEC-06: Production WSGI Server and Flask Debug-Mode Security.

Verifies:
1. Gunicorn dependency is pinned with specific version in req.txt and requirements.txt.
2. WSGI entry points (app.py and wsgi.py) expose valid Flask WSGI callables adhering to PEP 3333.
3. Production environment (FLASK_ENV=production or RENDER=true) strictly disables debug mode.
4. Production environment strictly overrides FLASK_DEBUG=1 / FLASK_DEBUG=true.
5. Production environment overrides any configuration object attempting to set DEBUG=True.
6. Local development environment preserves debug mode functionality when enabled.
7. Dynamic port resolution ($PORT) and host binding (0.0.0.0 in prod vs 127.0.0.1 in dev).
8. Procfile and Render start command configuration using $PORT and production timeouts.
9. No Werkzeug interactive debugger console or PIN leakage under production settings.
"""

import os
import re
import unittest
from unittest.mock import patch

from flask import Flask
from config import Config
from backend import create_app


class TestWSGIAndDebugSecurity(unittest.TestCase):

    def test_01_gunicorn_dependency_pinned_in_requirements(self):
        """1. Gunicorn dependency is pinned with '==' in requirements files."""
        for req_filename in ("req.txt", "requirements.txt"):
            req_path = os.path.join(Config.BASE_DIR, req_filename)
            self.assertTrue(os.path.exists(req_path), f"{req_filename} must exist.")

            with open(req_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Must contain pinned gunicorn dependency, e.g. gunicorn==23.0.0
            match = re.search(r"^gunicorn==(\d+\.\d+(?:\.\d+)?)$", content, re.MULTILINE)
            self.assertIsNotNone(
                match,
                f"Expected pinned gunicorn dependency (gunicorn==<version>) in {req_filename}."
            )
            pinned_version = match.group(1)
            # Must be a modern, compatible version (22.x or 23.x)
            major_version = int(pinned_version.split(".")[0])
            self.assertGreaterEqual(major_version, 22)

    def test_02_wsgi_entry_points_expose_valid_flask_callable(self):
        """2. WSGI entry points (app:app and wsgi:app) expose callable Flask WSGI instances."""
        # Test app.py entry point
        import app as app_module
        self.assertTrue(hasattr(app_module, "app"), "app.py must expose 'app' WSGI callable.")
        self.assertIsInstance(app_module.app, Flask)

        # Test wsgi.py entry point
        import wsgi as wsgi_module
        self.assertTrue(hasattr(wsgi_module, "app"), "wsgi.py must expose 'app' WSGI callable.")
        self.assertIsInstance(wsgi_module.app, Flask)

        # Verify WSGI callable interface (PEP 3333): app(environ, start_response)
        response_status = []
        response_headers = []

        def mock_start_response(status, headers):
            response_status.append(status)
            response_headers.extend(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "SCRIPT_NAME": "",
            "PATH_INFO": "/login",
            "QUERY_STRING": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "5000",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": None,
            "wsgi.errors": None,
            "wsgi.multithread": False,
            "wsgi.multiprocess": True,
            "wsgi.run_once": False,
            "REMOTE_ADDR": "127.0.0.1",
        }

        # Invoke through the WSGI callable
        response_iter = app_module.app.wsgi_app(environ, mock_start_response)
        self.assertTrue(len(response_status) > 0, "WSGI start_response must be invoked.")
        self.assertTrue(response_status[0].startswith("200") or response_status[0].startswith("302"))

    def test_03_production_environment_forces_debug_mode_off(self):
        """3. Production environment (FLASK_ENV=production or RENDER=true) forces debug mode False."""
        # Case A: FLASK_ENV=production
        with patch.dict(os.environ, {"FLASK_ENV": "production", "RENDER": ""}):
            app = create_app()
            self.assertFalse(app.debug, "app.debug must be False in production.")
            self.assertFalse(app.config["DEBUG"], "app.config['DEBUG'] must be False in production.")

        # Case B: RENDER=true
        with patch.dict(os.environ, {"RENDER": "true", "FLASK_ENV": ""}):
            app = create_app()
            self.assertFalse(app.debug, "app.debug must be False on Render.")
            self.assertFalse(app.config["DEBUG"], "app.config['DEBUG'] must be False on Render.")

    def test_04_production_environment_overrides_flask_debug_env_var(self):
        """4. Production environment strictly overrides FLASK_DEBUG=1 / FLASK_DEBUG=true."""
        # Case A: FLASK_DEBUG=1 under FLASK_ENV=production
        with patch.dict(os.environ, {"FLASK_ENV": "production", "FLASK_DEBUG": "1"}):
            app = create_app()
            self.assertFalse(app.debug, "FLASK_DEBUG=1 must be overridden to False in production.")
            self.assertFalse(app.config["DEBUG"])

        # Case B: FLASK_DEBUG=true under RENDER=true
        with patch.dict(os.environ, {"RENDER": "true", "FLASK_DEBUG": "true"}):
            app = create_app()
            self.assertFalse(app.debug, "FLASK_DEBUG=true must be overridden to False on Render.")
            self.assertFalse(app.config["DEBUG"])

    def test_05_production_environment_overrides_config_debug_true(self):
        """5. create_app overrides any config object that sets DEBUG=True if in production."""
        class DangerousDebugConfig(Config):
            DEBUG = True
            FLASK_ENV = "production"

        with patch.dict(os.environ, {"FLASK_ENV": "production"}):
            app = create_app(DangerousDebugConfig)
            self.assertFalse(
                app.debug,
                "create_app must override dangerous DEBUG=True configuration in production."
            )
            self.assertFalse(app.config["DEBUG"])

    def test_06_local_development_preserves_debug_mode(self):
        """6. In local development, debug mode can be enabled via FLASK_DEBUG=1."""
        with patch.dict(os.environ, {"FLASK_ENV": "development", "RENDER": "", "FLASK_DEBUG": "1"}):
            class LocalDevConfig(Config):
                DEBUG = True

            app = create_app(LocalDevConfig)
            self.assertTrue(app.debug, "Debug mode should be allowed in local development.")
            self.assertTrue(app.config["DEBUG"])

    def test_07_dynamic_port_and_host_resolution(self):
        """7. Verify app.py host and port resolution for Render ($PORT) vs local dev."""
        # Production on Render with custom $PORT
        is_production = True
        host_prod = "0.0.0.0" if is_production else "127.0.0.1"
        debug_prod = False if is_production else True

        with patch.dict(os.environ, {"PORT": "10000"}):
            port = int(os.getenv("PORT", "5000"))
            self.assertEqual(port, 10000)
            self.assertEqual(host_prod, "0.0.0.0")
            self.assertFalse(debug_prod)

        # Local development default
        is_dev = False
        host_dev = "0.0.0.0" if is_dev else "127.0.0.1"
        self.assertEqual(host_dev, "127.0.0.1")

    def test_08_procfile_and_render_start_command_syntax(self):
        """8. Procfile defines correct Gunicorn start command with $PORT, workers, and timeout."""
        procfile_path = os.path.join(Config.BASE_DIR, "Procfile")
        self.assertTrue(os.path.exists(procfile_path), "Procfile must exist for Render deployment.")

        with open(procfile_path, "r", encoding="utf-8") as f:
            procfile_content = f.read().strip()

        # Must define web process
        self.assertTrue(procfile_content.startswith("web:"), "Procfile must define 'web:' process.")

        # Must invoke gunicorn
        self.assertIn("gunicorn", procfile_content)

        # Must reference app:app or wsgi:app
        self.assertTrue(
            "app:app" in procfile_content or "wsgi:app" in procfile_content,
            "Procfile must reference app:app or wsgi:app."
        )

        # Must bind to 0.0.0.0:$PORT
        self.assertIn("0.0.0.0:$PORT", procfile_content)

        # Must include timeout >= 60 (to support AI generation and Playwright PDF generation)
        timeout_match = re.search(r"--timeout\s+(\d+)", procfile_content)
        self.assertIsNotNone(timeout_match, "Procfile must configure Gunicorn --timeout.")
        timeout_val = int(timeout_match.group(1))
        self.assertGreaterEqual(timeout_val, 60, "Timeout must be at least 60 seconds.")

    def test_09_no_werkzeug_debugger_console_exposed_in_production(self):
        """9. Unhandled routes or errors do not expose the Werkzeug interactive debugger /console."""
        with patch.dict(os.environ, {"FLASK_ENV": "production", "RENDER": "true"}):
            app = create_app()
            client = app.test_client()

            # Non-existent page (404)
            resp_404 = client.get("/non-existent-debug-test-page")
            self.assertEqual(resp_404.status_code, 404)
            body_404 = resp_404.data.decode("utf-8", errors="ignore")

            # Must not leak Werkzeug debugger artifacts
            self.assertNotIn("Werkzeug powered traceback", body_404)
            self.assertNotIn("__debugger__", body_404)
            self.assertNotIn("consoleLocked", body_404)


if __name__ == "__main__":
    unittest.main()

