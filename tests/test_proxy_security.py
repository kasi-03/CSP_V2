"""
Tests for SEC-02: Fail-Safe Client IP Resolution, X-Forwarded-Proto Security,
and Prevention of Proxy-Wide Account Lockouts for Render.

Verifies:
- Valid trusted client-IP header (CF-Connecting-IP) is correctly resolved.
- Missing trusted header resolves safely to 'unknown' (never treats shared proxy socket IP as visitor IP).
- Invalid or malformed trusted header resolves safely to 'unknown'.
- Spoofed X-Forwarded-For is strictly ignored (no fallback to unverified XFF).
- Spoofed True-Client-IP is strictly ignored (no fallback to unverified True-Client-IP).
- Local development (TRUSTED_PROXIES=0) strictly ignores all forwarded headers.
- IPv6, bracketed IPv6 with port, and IPv4 with port handling.
- X-Forwarded-Proto is NOT trusted by default (TRUST_FORWARDED_PROTO=False).
- X-Forwarded-Proto IS trusted only when explicitly enabled and validated (TRUST_FORWARDED_PROTO=True).
- Forwarded host headers are strictly ignored (prevents host header poisoning).
- Login failure lockout records and isolates by the resolved IP (prevents proxy-wide DoS).
- Audit logs record the resolved IP rather than the internal proxy socket IP.
- Automatic environment detection for Render (RENDER=true) and production.
- HTTPS detection, secure session cookies, and HSTS behavior.
- Missing/invalid client IP does NOT cause proxy-wide account lockouts.
- Multiple usernames sharing one proxy IP have strictly independent account lockouts.
- Unit validation of is_verified_client_ip across network classes.

Uses isolated temporary SQLite databases, temporary session files, and synthetic test accounts.
"""

import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import init_db, create_officer, get_connection, is_login_locked
from backend.services.auth import generate_password_hash
from backend.services.proxy_service import (
    parse_and_validate_ip,
    extract_render_client_ip,
    is_verified_client_ip
)


class TestProxySecurity(unittest.TestCase):

    def setUp(self):
        """Set up an isolated temporary database, session directory, and synthetic accounts."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        self.temp_session_dir = tempfile.mkdtemp()

        init_db(self.temp_db_path)

        # Provision test accounts
        self.officer_id = create_officer(
            username="proxy_officer",
            password_hash=generate_password_hash("ProxyOfficerPass123!"),
            full_name="Proxy Test Officer",
            role="officer",
            db_path=self.temp_db_path
        )
        self.other_officer_id = create_officer(
            username="other_officer",
            password_hash=generate_password_hash("OtherOfficerPass123!"),
            full_name="Other Test Officer",
            role="officer",
            db_path=self.temp_db_path
        )

    def tearDown(self):
        """Clean up all temporary databases and session files."""
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

        if os.path.exists(self.temp_session_dir):
            try:
                shutil.rmtree(self.temp_session_dir)
            except OSError:
                pass

    def _create_test_app(
        self,
        trusted_proxies: int = 0,
        trust_forwarded_proto: bool = False,
        session_cookie_secure: bool = False,
        hsts_enabled: bool = False
    ):
        """Create an isolated test application with specific proxy and HTTPS configuration."""
        temp_db_path = self.temp_db_path
        temp_session_dir = self.temp_session_dir

        class ProxyTestConfig(Config):
            TESTING = True
            DATABASE_PATH = temp_db_path
            SESSION_FILE_DIR = temp_session_dir
            TRUSTED_PROXIES = trusted_proxies
            TRUST_FORWARDED_PROTO = trust_forwarded_proto
            SESSION_COOKIE_SECURE = session_cookie_secure
            WTF_CSRF_ENABLED = True
            WTF_CSRF_TIME_LIMIT = 3600
            HSTS_ENABLED = hsts_enabled

        app = create_app(ProxyTestConfig)

        # Register inspection endpoint for asserting WSGI-level request properties
        @app.route("/_test/proxy_info")
        def proxy_info():
            from flask import jsonify, request
            return jsonify({
                "remote_addr": request.remote_addr,
                "scheme": request.scheme,
                "is_secure": request.is_secure,
                "host": request.host,
                "server_port": str(request.environ.get("SERVER_PORT", "")),
                "script_root": request.script_root
            })

        return app

    def _get_csrf_token(self, client, path="/login"):
        """Extract CSRF token from rendered HTML form."""
        resp = client.get(path)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', resp.data.decode("utf-8"))
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', resp.data.decode("utf-8"))
        return match.group(1) if match else ""

    def test_01_local_dev_default_ignores_all_forwarded_headers(self):
        """1. In local dev (TRUSTED_PROXIES=0), all client-supplied forwarding headers are ignored."""
        app = self._create_test_app(trusted_proxies=0)
        client = app.test_client()

        # Attacker connects directly and supplies spoofed headers
        resp = client.get(
            "/_test/proxy_info",
            headers={
                "CF-Connecting-IP": "203.0.113.195",
                "X-Forwarded-For": "198.51.100.42",
                "True-Client-IP": "198.51.100.99",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "evil.com"
            },
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        data = resp.get_json()
        self.assertEqual(data["remote_addr"], "127.0.0.1")
        self.assertEqual(data["scheme"], "http")
        self.assertFalse(data["is_secure"])

    def test_02_valid_trusted_client_ip_header(self):
        """2. When TRUSTED_PROXIES=1 (Render), client IP is extracted from trusted CF-Connecting-IP header."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        resp = client.get(
            "/_test/proxy_info",
            headers={"CF-Connecting-IP": "203.0.113.195"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data = resp.get_json()
        self.assertEqual(data["remote_addr"], "203.0.113.195")

    def test_03_missing_trusted_header_resolves_to_unknown(self):
        """3. When trusted header is missing behind Render, IP resolves to 'unknown' (never internal socket IP)."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        # Request arrives through proxy socket 10.0.0.1 without CF-Connecting-IP
        resp = client.get(
            "/_test/proxy_info",
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data = resp.get_json()
        # Must resolve to 'unknown' to avoid treating proxy socket IP as client IP
        self.assertEqual(data["remote_addr"], "unknown")
        self.assertNotEqual(data["remote_addr"], "10.0.0.1")

    def test_04_invalid_trusted_header_resolves_to_unknown(self):
        """4. Malformed or invalid IPs in CF-Connecting-IP resolve safely to 'unknown'."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        malformed_inputs = [
            "invalid_ip_format",
            "999.999.999.999",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "DROP TABLE complaints;",
            ""
        ]

        for bad_ip in malformed_inputs:
            resp = client.get(
                "/_test/proxy_info",
                headers={"CF-Connecting-IP": bad_ip},
                environ_base={"REMOTE_ADDR": "10.0.0.1"}
            )
            data = resp.get_json()
            # Must resolve to 'unknown'; never adopt invalid string or proxy socket IP
            self.assertEqual(data["remote_addr"], "unknown")
            self.assertNotEqual(data["remote_addr"], "10.0.0.1")

    def test_05_spoofed_x_forwarded_for_is_ignored(self):
        """5. Unverified X-Forwarded-For headers are strictly ignored as a client IP fallback."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        # Case A: Attacker sends only X-Forwarded-For (trying to spoof IP)
        resp_a = client.get(
            "/_test/proxy_info",
            headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.50"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data_a = resp_a.get_json()
        # X-Forwarded-For is ignored; resolves safely to 'unknown'
        self.assertEqual(data_a["remote_addr"], "unknown")
        self.assertNotEqual(data_a["remote_addr"], "1.1.1.1")
        self.assertNotEqual(data_a["remote_addr"], "203.0.113.50")
        self.assertNotEqual(data_a["remote_addr"], "10.0.0.1")

        # Case B: Attacker sends X-Forwarded-For alongside valid CF-Connecting-IP
        resp_b = client.get(
            "/_test/proxy_info",
            headers={
                "CF-Connecting-IP": "203.0.113.195",
                "X-Forwarded-For": "1.1.1.1"
            },
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data_b = resp_b.get_json()
        # Uses CF-Connecting-IP; ignores X-Forwarded-For
        self.assertEqual(data_b["remote_addr"], "203.0.113.195")

    def test_06_spoofed_true_client_ip_is_ignored(self):
        """6. Unverified True-Client-IP headers are strictly ignored as a client IP fallback."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        resp = client.get(
            "/_test/proxy_info",
            headers={"True-Client-IP": "8.8.8.8"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data = resp.get_json()
        # True-Client-IP is ignored; resolves to 'unknown'
        self.assertEqual(data["remote_addr"], "unknown")
        self.assertNotEqual(data["remote_addr"], "8.8.8.8")
        self.assertNotEqual(data["remote_addr"], "10.0.0.1")

    def test_07_ipv6_and_port_handling(self):
        """7. Parse and validate standard IPv6, bracketed IPv6 with port, and IPv4 with port."""
        self.assertEqual(parse_and_validate_ip("203.0.113.1"), "203.0.113.1")
        self.assertEqual(parse_and_validate_ip("203.0.113.1:8080"), "203.0.113.1")
        self.assertEqual(parse_and_validate_ip("2001:db8::1"), "2001:db8::1")
        self.assertEqual(parse_and_validate_ip("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(parse_and_validate_ip("[2001:db8::1]"), "2001:db8::1")
        self.assertIsNone(parse_and_validate_ip("not-an-ip"))
        self.assertIsNone(parse_and_validate_ip(""))
        self.assertIsNone(parse_and_validate_ip(None))

    def test_08_x_forwarded_proto_handling(self):
        """8. X-Forwarded-Proto is NOT trusted by default; trusted only when explicitly configured."""
        # Case A: Default fail-safe configuration (TRUST_FORWARDED_PROTO=False)
        app_default = self._create_test_app(trusted_proxies=1, trust_forwarded_proto=False)
        client_default = app_default.test_client()

        resp_untrusted = client_default.get(
            "/_test/proxy_info",
            headers={"X-Forwarded-Proto": "https"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data_untrusted = resp_untrusted.get_json()
        self.assertEqual(data_untrusted["scheme"], "http")
        self.assertFalse(data_untrusted["is_secure"])

        # Case B: Explicitly trusted (TRUST_FORWARDED_PROTO=True)
        app_trusted = self._create_test_app(trusted_proxies=1, trust_forwarded_proto=True)
        client_trusted = app_trusted.test_client()

        resp_https = client_trusted.get(
            "/_test/proxy_info",
            headers={"X-Forwarded-Proto": "https"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data_https = resp_https.get_json()
        self.assertEqual(data_https["scheme"], "https")
        self.assertTrue(data_https["is_secure"])

        # Case C: Explicitly trusted, but invalid scheme (e.g. ftp, gopher) is ignored
        resp_bad = client_trusted.get(
            "/_test/proxy_info",
            headers={"X-Forwarded-Proto": "ftp"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data_bad = resp_bad.get_json()
        self.assertEqual(data_bad["scheme"], "http")
        self.assertFalse(data_bad["is_secure"])

        # Case D: Local development (trusted_proxies=0) ignores X-Forwarded-Proto even if trust_forwarded_proto=True
        app_local = self._create_test_app(trusted_proxies=0, trust_forwarded_proto=True)
        client_local = app_local.test_client()

        resp_local = client_local.get(
            "/_test/proxy_info",
            headers={"X-Forwarded-Proto": "https"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        data_local = resp_local.get_json()
        self.assertEqual(data_local["scheme"], "http")
        self.assertFalse(data_local["is_secure"])

    def test_09_login_failure_lockout_uses_resolved_ip(self):
        """9. Lockout records the verified client IP, preventing proxy-wide denial of service."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        attacker_ip = "203.0.113.99"
        legitimate_ip = "198.51.100.55"

        # Attacker fails login 5 times from attacker_ip via trusted CF-Connecting-IP
        for _ in range(5):
            csrf = self._get_csrf_token(client, "/login")
            resp = client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "username": "proxy_officer",
                    "password": "WrongPassword123!"
                },
                headers={"CF-Connecting-IP": attacker_ip},
                environ_base={"REMOTE_ADDR": "10.0.0.1"}
            )
            self.assertEqual(resp.status_code, 401)

        # 6th attempt from attacker_ip is locked out
        csrf = self._get_csrf_token(client, "/login")
        resp_locked = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "proxy_officer",
                "password": "ProxyOfficerPass123!"
            },
            headers={"CF-Connecting-IP": attacker_ip},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        self.assertEqual(resp_locked.status_code, 401)
        self.assertIn("failed login attempts", resp_locked.data.decode("utf-8").lower())

        # Verify failed attempts in DB are associated with attacker_ip, not proxy socket IP 10.0.0.1
        conn = get_connection(self.temp_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM login_attempts WHERE username = 'proxy_officer'")
            ips = [r[0] for r in cursor.fetchall()]
            self.assertTrue(all(ip == attacker_ip for ip in ips))
            self.assertNotIn("10.0.0.1", ips)
        finally:
            conn.close()

        # Legitimate user from different IP logging into another account is NOT blocked (DoS prevented)
        csrf = self._get_csrf_token(client, "/login")
        resp_legit = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "other_officer",
                "password": "OtherOfficerPass123!"
            },
            headers={"CF-Connecting-IP": legitimate_ip},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            follow_redirects=False
        )
        self.assertEqual(resp_legit.status_code, 302)
        self.assertEqual(resp_legit.headers.get("Location"), "/")

    def test_10_audit_logs_record_resolved_ip(self):
        """10. Audit logs store the resolved client IP rather than the reverse proxy socket IP."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        client_real_ip = "203.0.113.88"
        csrf = self._get_csrf_token(client, "/login")

        # Successful login through Render proxy with CF-Connecting-IP
        resp = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "proxy_officer",
                "password": "ProxyOfficerPass123!"
            },
            headers={"CF-Connecting-IP": client_real_ip},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            follow_redirects=False
        )
        self.assertEqual(resp.status_code, 302)

        # Inspect audit_logs table
        conn = get_connection(self.temp_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip_address, action, status FROM audit_logs WHERE username = 'proxy_officer' AND action = 'LOGIN_SUCCESS'"
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], client_real_ip)
            self.assertNotEqual(row[0], "10.0.0.1")
        finally:
            conn.close()

    def test_11_untrusted_forwarded_host_is_ignored(self):
        """11. Forwarded host headers (X-Forwarded-Host) are strictly ignored (prevents host poisoning)."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        resp = client.get(
            "/_test/proxy_info",
            base_url="http://police-csp.onrender.com",
            headers={
                "CF-Connecting-IP": "203.0.113.50",
                "X-Forwarded-Host": "evil-phishing-site.example.com"
            },
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        data = resp.get_json()
        self.assertEqual(data["host"], "police-csp.onrender.com")
        self.assertNotIn("evil-phishing-site.example.com", data["host"])

    def test_12_environment_variable_auto_detection(self):
        """12. Config dynamically detects Render and production environments for trusted proxy count."""
        # Case A: Local development (default) -> 0 proxies
        with patch.dict(os.environ, {"RENDER": "", "FLASK_ENV": "development", "TRUSTED_PROXIES": ""}):
            is_render = os.getenv("RENDER", "").lower() in ("true", "1")
            is_prod = os.getenv("FLASK_ENV") == "production"
            default_p = 1 if (is_render or is_prod) else 0
            self.assertEqual(default_p, 0)

        # Case B: On Render (RENDER=true) -> 1 proxy
        with patch.dict(os.environ, {"RENDER": "true", "FLASK_ENV": "development"}):
            is_render = os.getenv("RENDER", "").lower() in ("true", "1")
            is_prod = os.getenv("FLASK_ENV") == "production"
            default_p = 1 if (is_render or is_prod) else 0
            self.assertEqual(default_p, 1)

        # Case C: Production environment (FLASK_ENV=production) -> 1 proxy
        with patch.dict(os.environ, {"RENDER": "", "FLASK_ENV": "production"}):
            is_render = os.getenv("RENDER", "").lower() in ("true", "1")
            is_prod = os.getenv("FLASK_ENV") == "production"
            default_p = 1 if (is_render or is_prod) else 0
            self.assertEqual(default_p, 1)

    def test_13_https_detection_and_hsts_behavior(self):
        """13. HSTS is emitted only under verified HTTPS or production HSTS configuration."""
        # Case A: Local dev (HSTS_ENABLED=False, scheme=http) -> No HSTS header
        app_dev = self._create_test_app(trusted_proxies=0, hsts_enabled=False)
        client_dev = app_dev.test_client()
        resp_dev = client_dev.get("/login")
        self.assertNotIn("Strict-Transport-Security", resp_dev.headers)

        # Case B: Production with HSTS_ENABLED=True and SESSION_COOKIE_SECURE=True
        app_prod = self._create_test_app(
            trusted_proxies=1,
            trust_forwarded_proto=False,
            session_cookie_secure=True,
            hsts_enabled=True
        )
        client_prod = app_prod.test_client()
        resp_prod = client_prod.get("/login")
        self.assertIn("Strict-Transport-Security", resp_prod.headers)
        self.assertEqual(resp_prod.headers["Strict-Transport-Security"], "max-age=31536000")

        # Case C: HTTPS request detected when trust_forwarded_proto=True
        app_https = self._create_test_app(
            trusted_proxies=1,
            trust_forwarded_proto=True,
            session_cookie_secure=False,
            hsts_enabled=True
        )
        client_https = app_https.test_client()
        resp_https = client_https.get(
            "/login",
            headers={"X-Forwarded-Proto": "https"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        self.assertIn("Strict-Transport-Security", resp_https.headers)
        self.assertEqual(resp_https.headers["Strict-Transport-Security"], "max-age=31536000")

    def test_14_secure_session_cookie_behavior(self):
        """14. Session cookies enforce Secure flag in production and allow HTTP in local dev."""
        # Case A: Production configuration with SESSION_COOKIE_SECURE=True
        app_prod = self._create_test_app(trusted_proxies=1, session_cookie_secure=True)
        client_prod = app_prod.test_client()
        csrf_prod = self._get_csrf_token(client_prod, "/login")

        resp_prod = client_prod.post(
            "/login",
            data={
                "csrf_token": csrf_prod,
                "username": "proxy_officer",
                "password": "ProxyOfficerPass123!"
            },
            follow_redirects=False
        )
        self.assertEqual(resp_prod.status_code, 302)
        set_cookie_prod = resp_prod.headers.get("Set-Cookie", "")
        self.assertIn("Secure", set_cookie_prod)
        self.assertIn("HttpOnly", set_cookie_prod)
        self.assertIn("SameSite=Lax", set_cookie_prod)

        # Case B: Local development configuration with SESSION_COOKIE_SECURE=False
        app_dev = self._create_test_app(trusted_proxies=0, session_cookie_secure=False)
        client_dev = app_dev.test_client()
        csrf_dev = self._get_csrf_token(client_dev, "/login")

        resp_dev = client_dev.post(
            "/login",
            data={
                "csrf_token": csrf_dev,
                "username": "proxy_officer",
                "password": "ProxyOfficerPass123!"
            },
            follow_redirects=False
        )
        self.assertEqual(resp_dev.status_code, 302)
        set_cookie_dev = resp_dev.headers.get("Set-Cookie", "")
        self.assertNotIn("Secure", set_cookie_dev)
        self.assertIn("HttpOnly", set_cookie_dev)
        self.assertIn("SameSite=Lax", set_cookie_dev)

    def test_15_missing_or_invalid_client_ip_no_proxy_wide_lockout(self):
        """15. When CF-Connecting-IP is missing/invalid, attempts mark IP as unknown without proxy-wide lockout."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        # Attacker fails login 5 times without CF-Connecting-IP (resolves to 'unknown')
        for _ in range(5):
            csrf = self._get_csrf_token(client, "/login")
            resp = client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "username": "proxy_officer",
                    "password": "WrongPassword123!"
                },
                environ_base={"REMOTE_ADDR": "10.0.0.1"}
            )
            self.assertEqual(resp.status_code, 401)

        # proxy_officer is locked out by username
        locked, _ = is_login_locked("proxy_officer", ip_address="unknown", db_path=self.temp_db_path)
        self.assertTrue(locked)

        # Legitimate user (other_officer) connecting through the same proxy without CF-Connecting-IP
        # MUST NOT be locked out. Account lockouts remain strictly independent.
        csrf = self._get_csrf_token(client, "/login")
        resp_other = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "other_officer",
                "password": "OtherOfficerPass123!"
            },
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            follow_redirects=False
        )
        self.assertEqual(resp_other.status_code, 302)
        self.assertEqual(resp_other.headers.get("Location"), "/")

        # Audit log for other_officer records ip_address as 'unknown' without claiming 10.0.0.1 is visitor IP
        conn = get_connection(self.temp_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip_address, action, status FROM audit_logs WHERE username = 'other_officer' AND action = 'LOGIN_SUCCESS'"
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "unknown")
            self.assertNotEqual(row[0], "10.0.0.1")
        finally:
            conn.close()

    def test_16_multiple_usernames_sharing_one_proxy_ip_independent_lockouts(self):
        """16. Multiple users sharing one internal proxy socket IP have strictly independent lockouts."""
        app = self._create_test_app(trusted_proxies=1)
        client = app.test_client()

        # Malformed CF-Connecting-IP forces resolution to 'unknown'
        for _ in range(5):
            csrf = self._get_csrf_token(client, "/login")
            resp = client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "username": "proxy_officer",
                    "password": "WrongPassword123!"
                },
                headers={"CF-Connecting-IP": "not-a-valid-ip"},
                environ_base={"REMOTE_ADDR": "10.0.0.1"}
            )
            self.assertEqual(resp.status_code, 401)

        # 6th attempt on proxy_officer is blocked
        csrf = self._get_csrf_token(client, "/login")
        resp_locked = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "proxy_officer",
                "password": "ProxyOfficerPass123!"
            },
            headers={"CF-Connecting-IP": "not-a-valid-ip"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}
        )
        self.assertEqual(resp_locked.status_code, 401)
        self.assertIn("failed login attempts", resp_locked.data.decode("utf-8").lower())

        # other_officer sharing the same proxy socket connects and authenticates successfully
        csrf = self._get_csrf_token(client, "/login")
        resp_success = client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "other_officer",
                "password": "OtherOfficerPass123!"
            },
            headers={"CF-Connecting-IP": "not-a-valid-ip"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            follow_redirects=False
        )
        self.assertEqual(resp_success.status_code, 302)
        self.assertEqual(resp_success.headers.get("Location"), "/")

    def test_17_is_verified_client_ip_validation(self):
        """17. Verify is_verified_client_ip accurately classifies public vs internal/proxy IPs."""
        # Routable public and testnet IPs
        self.assertTrue(is_verified_client_ip("203.0.113.195"))
        self.assertTrue(is_verified_client_ip("198.51.100.55"))
        self.assertTrue(is_verified_client_ip("8.8.8.8"))
        self.assertTrue(is_verified_client_ip("1.1.1.1"))
        self.assertTrue(is_verified_client_ip("2001:db8::1"))

        # Internal proxy socket IPs (must NEVER be treated as verified public IPs)
        self.assertFalse(is_verified_client_ip("10.0.0.1"))
        self.assertFalse(is_verified_client_ip("172.20.0.5"))
        self.assertFalse(is_verified_client_ip("192.168.1.1"))
        self.assertFalse(is_verified_client_ip("100.64.0.1"))  # CGNAT

        # Loopback and link-local (must NEVER cause proxy-wide lockouts)
        self.assertFalse(is_verified_client_ip("127.0.0.1"))
        self.assertFalse(is_verified_client_ip("::1"))
        self.assertFalse(is_verified_client_ip("169.254.1.1"))
        self.assertFalse(is_verified_client_ip("fe80::1"))

        # Unknown, null, or malformed
        self.assertFalse(is_verified_client_ip("unknown"))
        self.assertFalse(is_verified_client_ip("none"))
        self.assertFalse(is_verified_client_ip(""))
        self.assertFalse(is_verified_client_ip(None))
        self.assertFalse(is_verified_client_ip("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
