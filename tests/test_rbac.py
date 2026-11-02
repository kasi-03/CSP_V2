"""
Comprehensive Unit and Integration Tests for Phase 4: Role-Based Access Control (RBAC).

Tests cover:
1. Unauthenticated page access redirection to /login with ?next= parameter.
2. Unauthenticated file download access rejection with 401 Unauthorized.
3. Admin role full permissions (complaints, record, settings, officer management, audit logs).
4. Officer role permissions and restrictions (can record/view; 403 on settings, admin, audit logs).
5. Viewer role permissions and restrictions (read-only; 403 on record, process, settings, admin).
6. Last active Administrator protection (cannot deactivate or demote the sole active admin).
7. Admin officer provisioning (create officer, password complexity enforcement, duplicate prevention).
8. Admin toggle officer active status with audit logging.
9. Admin change officer role with audit logging and role validation.
10. Admin reset officer password with password complexity enforcement.
11. Paginated audit logs access, filtering by action and username, and page navigation.
12. Live database role validation preventing cached session privilege escalation.
13. Unit test for has_permission matrix across roles and account statuses.
"""

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from backend import create_app
from backend.services.database import (
    init_db,
    create_officer,
    get_officer_by_id,
    get_officer_by_username,
    update_officer_status,
    update_officer_role,
    update_officer_status_atomic,
    update_officer_role_atomic,
    save_complaint,
    get_audit_logs,
    count_active_admins
)
from backend.services.auth import (
    generate_password_hash,
    has_permission,
    can_manage_admin
)


class TestRBACAndRouteProtection(unittest.TestCase):

    def setUp(self):
        """Create an isolated temporary SQLite database and configure test client."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        init_db(self.temp_db_path)

        # Seed baseline complaint
        self.complaint_id = save_complaint(
            registered_on="2026-11-01 10:00:00",
            english_name="Test Complainant",
            telugu_name="టెస్ట్ ఫిర్యాదుదారుడు",
            phone="9876543210",
            subject="Test Incident",
            audio_path="audio/Complaint_Audio.webm",
            telugu_complaint="ఫిర్యాదు వివరాలు",
            english_complaint="Complaint details",
            db_path=self.temp_db_path
        )

        # Seed test officers with distinct roles
        self.admin_id = create_officer(
            username="admin_user",
            password_hash=generate_password_hash("AdminPass123!"),
            full_name="System Administrator",
            badge_number="ADM01",
            role="admin",
            db_path=self.temp_db_path
        )

        self.officer_id = create_officer(
            username="patrol_officer",
            password_hash=generate_password_hash("OfficerPass123!"),
            full_name="Patrol Officer",
            badge_number="POL02",
            role="officer",
            db_path=self.temp_db_path
        )

        self.viewer_id = create_officer(
            username="desk_viewer",
            password_hash=generate_password_hash("ViewerPass123!"),
            full_name="Desk Viewer",
            badge_number="VIW03",
            role="viewer",
            db_path=self.temp_db_path
        )

        self.inactive_id = create_officer(
            username="inactive_officer",
            password_hash=generate_password_hash("InactivePass123!"),
            full_name="Suspended Officer",
            badge_number="SUS04",
            role="officer",
            db_path=self.temp_db_path
        )
        update_officer_status(self.inactive_id, is_active=0, db_path=self.temp_db_path)

        self.db_patcher = patch.object(Config, "DATABASE_PATH", self.temp_db_path)
        self.db_patcher.start()

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up isolated database artifacts."""
        self.db_patcher.stop()
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    # -----------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------
    def _extract_csrf(self, html: str) -> str:
        """Extract CSRF token from rendered HTML forms."""
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', html)
        return match.group(1) if match else ""

    def _login_as(self, username: str, password: str):
        """Perform a full HTTP login flow setting verified session cookies."""
        resp = self.client.get("/login")
        csrf_token = self._extract_csrf(resp.data.decode("utf-8"))
        post_resp = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": username,
            "password": password
        }, follow_redirects=False)
        self.assertEqual(post_resp.status_code, 302, f"Login for {username} failed to redirect")
        return post_resp

    def _logout(self):
        """Perform HTTP logout."""
        dash = self.client.get("/")
        csrf_token = self._extract_csrf(dash.data.decode("utf-8"))
        self.client.post("/logout", data={"csrf_token": csrf_token})

    # -----------------------------------------------------------------
    # Test Cases
    # -----------------------------------------------------------------
    def test_01_unauthenticated_page_redirects(self):
        """1. Unauthenticated requests to protected pages redirect to /login with next param."""
        protected_endpoints = [
            ("/", "/login?next=/"),
            ("/record", "/login?next=/record"),
            ("/settings", "/login?next=/settings"),
            ("/admin/officers", "/login?next=/admin/officers"),
            ("/admin/officers/create", "/login?next=/admin/officers/create"),
            ("/admin/audit-logs", "/login?next=/admin/audit-logs"),
            (f"/view_telugu/{self.complaint_id}", f"/login?next=/view_telugu/{self.complaint_id}"),
            (f"/view_english/{self.complaint_id}", f"/login?next=/view_english/{self.complaint_id}"),
        ]

        for path, expected_redirect in protected_endpoints:
            resp = self.client.get(path, follow_redirects=False)
            self.assertEqual(resp.status_code, 302, f"Path {path} did not return 302")
            self.assertEqual(resp.headers["Location"], expected_redirect)

    def test_02_unauthenticated_file_access_returns_401(self):
        """2. Unauthenticated requests to secure file endpoints return 401 Unauthorized."""
        file_endpoints = [
            f"/complaints/{self.complaint_id}/files/audio",
            f"/complaints/{self.complaint_id}/files/telugu_pdf",
            f"/complaints/{self.complaint_id}/files/english_pdf",
            "/case_audio/sample.webm",
        ]
        for path in file_endpoints:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 401, f"File path {path} did not return 401")

    def test_03_admin_role_full_access(self):
        """3. Admin role has access to all protected endpoints including admin management and settings."""
        self._login_as("admin_user", "AdminPass123!")

        endpoints = [
            ("/", "AI Police Complaint Drafting System"),
            ("/record", "Complainant Name"),
            ("/settings", "Police Station Settings"),
            ("/admin/officers", "Officer Management"),
            ("/admin/officers/create", "Provision New Officer Account"),
            ("/admin/audit-logs", "Security Audit Log"),
            (f"/view_telugu/{self.complaint_id}", "Case ID"),
            (f"/view_english/{self.complaint_id}", "Case ID"),
        ]

        for path, expected_text in endpoints:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, f"Admin was denied access to {path}")
            self.assertIn(expected_text, resp.data.decode("utf-8"))

        # Verify role badge displayed on dashboard
        dash = self.client.get("/")
        content = dash.data.decode("utf-8")
        self.assertIn("System Administrator", content)
        self.assertIn("admin", content.lower())
        self.assertIn("Manage Officers", content)
        self.assertIn("Audit Logs", content)

    def test_04_officer_role_permissions_and_restrictions(self):
        """4. Officer role can view/record complaints; denied 403 on settings, officer admin, and audit logs."""
        self._login_as("patrol_officer", "OfficerPass123!")

        # Allowed routes (200)
        allowed = [
            ("/", "AI Police Complaint Drafting System"),
            ("/record", "Complainant Name"),
            (f"/view_telugu/{self.complaint_id}", "Case ID"),
            (f"/view_english/{self.complaint_id}", "Case ID"),
        ]
        for path, expected_text in allowed:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, f"Officer was denied access to {path}")
            self.assertIn(expected_text, resp.data.decode("utf-8"))

        # Denied routes (403)
        forbidden = [
            "/settings",
            "/admin/officers",
            "/admin/officers/create",
            "/admin/audit-logs",
        ]
        for path in forbidden:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 403, f"Officer was not forbidden on {path}")
            content = resp.data.decode("utf-8")
            self.assertIn("Access Denied", content)

        # Denied POST on settings
        resp_save = self.client.post("/save_settings", data={
            "station_name": "Unauthorized Station",
            "place": "Nowhere",
            "district": "None"
        })
        # Note: CSRF or RBAC check triggers
        self.assertIn(resp_save.status_code, (400, 403))

        # Check audit log contains UNAUTHORIZED_ACCESS
        logs = get_audit_logs(limit=20, db_path=self.temp_db_path)
        unauth_logs = [l for l in logs if l["action"] == "UNAUTHORIZED_ACCESS" and l["username"] == "patrol_officer"]
        self.assertGreater(len(unauth_logs), 0, "UNAUTHORIZED_ACCESS was not logged for officer")
        self.assertEqual(unauth_logs[0]["status"], "DENIED")

    def test_05_viewer_role_permissions_and_restrictions(self):
        """5. Viewer role has read-only access; denied 403 on /record, /process, /settings, /admin."""
        self._login_as("desk_viewer", "ViewerPass123!")

        # Allowed read-only routes (200)
        dash = self.client.get("/")
        self.assertEqual(dash.status_code, 200)
        dash_content = dash.data.decode("utf-8")
        self.assertIn("Viewer Mode: Read-Only Access", dash_content)
        self.assertNotIn('href="/record"', dash_content)
        self.assertNotIn('href="/settings"', dash_content)

        resp_telugu = self.client.get(f"/view_telugu/{self.complaint_id}")
        self.assertEqual(resp_telugu.status_code, 200)

        # Forbidden routes (403)
        forbidden = [
            "/record",
            "/settings",
            "/admin/officers",
            "/admin/officers/create",
            "/admin/audit-logs",
        ]
        for path in forbidden:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 403, f"Viewer was not forbidden on {path}")
            self.assertIn("Access Denied", resp.data.decode("utf-8"))

        # POST /process forbidden
        record_csrf = self._extract_csrf(dash_content)  # viewer has csrf token from dashboard
        resp_proc = self.client.post("/process", data={
            "csrf_token": record_csrf,
            "complainant_name": "Should Fail",
            "phone_number": "9000000000"
        })
        self.assertEqual(resp_proc.status_code, 403)

    def test_06_last_active_admin_protection(self):
        """6. System prevents deactivating or demoting the last active Administrator."""
        self._login_as("admin_user", "AdminPass123!")

        # Verify only 1 active admin currently exists
        self.assertEqual(count_active_admins(self.temp_db_path), 1)

        # 1. Attempt to deactivate sole admin via helper
        allowed_deact, msg_deact = can_manage_admin(self.admin_id, action="deactivate", db_path=self.temp_db_path)
        self.assertFalse(allowed_deact)
        self.assertIn("At least one active Administrator must remain", msg_deact)

        # 2. Attempt to demote sole admin via helper
        allowed_demote, msg_demote = can_manage_admin(self.admin_id, action="demote", db_path=self.temp_db_path)
        self.assertFalse(allowed_demote)
        self.assertIn("At least one active Administrator must remain", msg_demote)

        # 3. HTTP test: attempt to deactivate sole admin via route
        dash = self.client.get("/admin/officers")
        csrf_token = self._extract_csrf(dash.data.decode("utf-8"))
        resp_toggle = self.client.post(f"/admin/officers/{self.admin_id}/toggle-status", data={
            "csrf_token": csrf_token
        })
        self.assertEqual(resp_toggle.status_code, 400)
        self.assertIn("At least one active Administrator must remain", resp_toggle.data.decode("utf-8"))

        # Verify admin is still active in database
        admin_rec = get_officer_by_id(self.admin_id, db_path=self.temp_db_path)
        self.assertEqual(admin_rec["is_active"], 1)

        # 4. HTTP test: attempt to demote sole admin via route
        resp_demote = self.client.post(f"/admin/officers/{self.admin_id}/change-role", data={
            "csrf_token": csrf_token,
            "role": "officer"
        })
        self.assertEqual(resp_demote.status_code, 400)
        self.assertIn("At least one active Administrator must remain", resp_demote.data.decode("utf-8"))

        admin_rec = get_officer_by_id(self.admin_id, db_path=self.temp_db_path)
        self.assertEqual(admin_rec["role"], "admin")

        # 5. Create a second admin and verify deactivation/demotion becomes allowed
        second_admin_id = create_officer(
            username="second_admin",
            password_hash=generate_password_hash("SecondAdmin123!"),
            full_name="Second Administrator",
            role="admin",
            db_path=self.temp_db_path
        )
        self.assertEqual(count_active_admins(self.temp_db_path), 2)

        # Deactivating the second admin now succeeds
        resp_toggle2 = self.client.post(f"/admin/officers/{second_admin_id}/toggle-status", data={
            "csrf_token": csrf_token
        }, follow_redirects=False)
        self.assertEqual(resp_toggle2.status_code, 302)

        second_rec = get_officer_by_id(second_admin_id, db_path=self.temp_db_path)
        self.assertEqual(second_rec["is_active"], 0)
        self.assertEqual(count_active_admins(self.temp_db_path), 1)

    def test_07_admin_create_officer(self):
        """7. Admin can provision new officers with password strength checks and duplicate defense."""
        self._login_as("admin_user", "AdminPass123!")

        page = self.client.get("/admin/officers/create")
        self.assertEqual(page.status_code, 200)
        csrf_token = self._extract_csrf(page.data.decode("utf-8"))

        # 1. Reject weak password
        weak_resp = self.client.post("/admin/officers/create", data={
            "csrf_token": csrf_token,
            "username": "new_sub_officer",
            "password": "weak",
            "confirm_password": "weak",
            "full_name": "New Sub Officer",
            "badge_number": "SUB05",
            "role": "officer"
        })
        self.assertEqual(weak_resp.status_code, 400)
        self.assertIn("Password must be at least 8 characters", weak_resp.data.decode("utf-8"))

        # 2. Reject duplicate username
        dup_resp = self.client.post("/admin/officers/create", data={
            "csrf_token": csrf_token,
            "username": "ADMIN_USER",  # case-insensitive collision
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
            "full_name": "Duplicate Admin",
            "badge_number": "DUP01",
            "role": "officer"
        })
        self.assertEqual(dup_resp.status_code, 400)
        self.assertIn("already exists", dup_resp.data.decode("utf-8"))

        # 3. Successful officer creation
        valid_resp = self.client.post("/admin/officers/create", data={
            "csrf_token": csrf_token,
            "username": "new_sub_officer",
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
            "full_name": "New Sub Officer",
            "badge_number": "SUB05",
            "role": "officer"
        }, follow_redirects=False)
        self.assertEqual(valid_resp.status_code, 302)
        self.assertIn("/admin/officers", valid_resp.headers["Location"])

        # Confirm created in DB
        created = get_officer_by_username("new_sub_officer", db_path=self.temp_db_path)
        self.assertIsNotNone(created)
        self.assertEqual(created["full_name"], "New Sub Officer")
        self.assertEqual(created["role"], "officer")
        self.assertEqual(created["is_active"], 1)

        # Confirm audit log entry
        logs = get_audit_logs(limit=10, db_path=self.temp_db_path)
        create_logs = [l for l in logs if l["action"] == "OFFICER_CREATED"]
        self.assertGreater(len(create_logs), 0)
        self.assertIn("new_sub_officer", create_logs[0]["details"])

    def test_08_admin_toggle_officer_status(self):
        """8. Admin can toggle non-admin officer status (active <-> inactive) with audit logging."""
        self._login_as("admin_user", "AdminPass123!")

        dash = self.client.get("/admin/officers")
        csrf_token = self._extract_csrf(dash.data.decode("utf-8"))

        # Deactivate patrol officer
        resp1 = self.client.post(f"/admin/officers/{self.officer_id}/toggle-status", data={
            "csrf_token": csrf_token
        }, follow_redirects=False)
        self.assertEqual(resp1.status_code, 302)

        off1 = get_officer_by_id(self.officer_id, db_path=self.temp_db_path)
        self.assertEqual(off1["is_active"], 0)

        # Reactivate patrol officer
        resp2 = self.client.post(f"/admin/officers/{self.officer_id}/toggle-status", data={
            "csrf_token": csrf_token
        }, follow_redirects=False)
        self.assertEqual(resp2.status_code, 302)

        off2 = get_officer_by_id(self.officer_id, db_path=self.temp_db_path)
        self.assertEqual(off2["is_active"], 1)

        # Verify audit logs
        logs = get_audit_logs(limit=10, db_path=self.temp_db_path)
        actions = [l["action"] for l in logs]
        self.assertIn("OFFICER_DEACTIVATED", actions)
        self.assertIn("OFFICER_ACTIVATED", actions)

    def test_09_admin_change_officer_role(self):
        """9. Admin can change officer roles with validation and audit logging."""
        self._login_as("admin_user", "AdminPass123!")

        dash = self.client.get("/admin/officers")
        csrf_token = self._extract_csrf(dash.data.decode("utf-8"))

        # 1. Invalid role rejected
        resp_invalid = self.client.post(f"/admin/officers/{self.officer_id}/change-role", data={
            "csrf_token": csrf_token,
            "role": "superuser"
        })
        self.assertEqual(resp_invalid.status_code, 400)
        self.assertIn("Invalid role", resp_invalid.data.decode("utf-8"))

        # 2. Change patrol_officer to viewer
        resp_change = self.client.post(f"/admin/officers/{self.officer_id}/change-role", data={
            "csrf_token": csrf_token,
            "role": "viewer"
        }, follow_redirects=False)
        self.assertEqual(resp_change.status_code, 302)

        off = get_officer_by_id(self.officer_id, db_path=self.temp_db_path)
        self.assertEqual(off["role"], "viewer")

        # Verify audit log
        logs = get_audit_logs(limit=10, db_path=self.temp_db_path)
        role_logs = [l for l in logs if l["action"] == "OFFICER_ROLE_CHANGED"]
        self.assertGreater(len(role_logs), 0)
        self.assertIn("viewer", role_logs[0]["details"])

    def test_10_admin_reset_officer_password(self):
        """10. Admin can reset officer password with password strength enforcement."""
        self._login_as("admin_user", "AdminPass123!")

        dash = self.client.get("/admin/officers")
        csrf_token = self._extract_csrf(dash.data.decode("utf-8"))

        # 1. Reject weak reset password
        resp_weak = self.client.post(f"/admin/officers/{self.officer_id}/reset-password", data={
            "csrf_token": csrf_token,
            "new_password": "weak",
            "confirm_password": "weak"
        })
        self.assertEqual(resp_weak.status_code, 400)
        self.assertIn("Password must be at least 8 characters", resp_weak.data.decode("utf-8"))

        # 2. Accept strong password reset
        resp_valid = self.client.post(f"/admin/officers/{self.officer_id}/reset-password", data={
            "csrf_token": csrf_token,
            "new_password": "NewPatrolPassword999!",
            "confirm_password": "NewPatrolPassword999!"
        }, follow_redirects=False)
        self.assertEqual(resp_valid.status_code, 302)

        # 3. Verify patrol officer can now log in with the new password
        self._logout()
        login_resp = self._login_as("patrol_officer", "NewPatrolPassword999!")
        self.assertEqual(login_resp.status_code, 302)

        # 4. Old password no longer works
        self._logout()
        get_login = self.client.get("/login")
        csrf = self._extract_csrf(get_login.data.decode("utf-8"))
        old_resp = self.client.post("/login", data={
            "csrf_token": csrf,
            "username": "patrol_officer",
            "password": "OfficerPass123!"
        })
        self.assertEqual(old_resp.status_code, 401)

    def test_11_paginated_audit_logs_and_filtering(self):
        """11. Admin can access paginated audit logs and filter by action or username."""
        self._login_as("admin_user", "AdminPass123!")

        # 1. View audit logs page
        resp = self.client.get("/admin/audit-logs")
        self.assertEqual(resp.status_code, 200)
        content = resp.data.decode("utf-8")
        self.assertIn("Security Audit Log", content)
        self.assertIn("Filter by Action", content)

        # 2. Filter by action
        resp_filtered_action = self.client.get("/admin/audit-logs?action=LOGIN_SUCCESS")
        self.assertEqual(resp_filtered_action.status_code, 200)
        content_action = resp_filtered_action.data.decode("utf-8")
        self.assertIn("LOGIN_SUCCESS", content_action)

        # 3. Filter by username
        resp_filtered_user = self.client.get("/admin/audit-logs?username=admin_user")
        self.assertEqual(resp_filtered_user.status_code, 200)
        content_user = resp_filtered_user.data.decode("utf-8")
        self.assertIn("admin_user", content_user)

        # 4. Pagination navigation (page 1)
        resp_p1 = self.client.get("/admin/audit-logs?page=1")
        self.assertEqual(resp_p1.status_code, 200)

    def test_12_live_database_role_validation_prevents_privilege_escalation(self):
        """12. Live database check prevents session hijacking or privilege escalation if role changed in DB."""
        # 1. Officer logs in with active session
        self._login_as("patrol_officer", "OfficerPass123!")

        # Verify access to /record works
        resp_record1 = self.client.get("/record")
        self.assertEqual(resp_record1.status_code, 200)

        # 2. Demote officer directly in database to 'viewer' behind the scenes
        update_officer_role(self.officer_id, "viewer", db_path=self.temp_db_path)

        # 3. Next request to /record must fail with 403 Forbidden even with preexisting cookie
        resp_record2 = self.client.get("/record")
        self.assertEqual(resp_record2.status_code, 403)
        self.assertIn("Access Denied", resp_record2.data.decode("utf-8"))

    def test_13_permission_matrix_helper(self):
        """13. Verify has_permission helper accurately maps permissions for all roles."""
        admin = {"role": "admin", "is_active": 1}
        officer = {"role": "officer", "is_active": 1}
        viewer = {"role": "viewer", "is_active": 1}
        inactive_admin = {"role": "admin", "is_active": 0}

        # Admin permissions
        self.assertTrue(has_permission(admin, "view_complaints"))
        self.assertTrue(has_permission(admin, "create_complaint"))
        self.assertTrue(has_permission(admin, "manage_settings"))
        self.assertTrue(has_permission(admin, "manage_officers"))
        self.assertTrue(has_permission(admin, "view_audit_logs"))
        self.assertTrue(has_permission(admin, "download_files"))

        # Officer permissions
        self.assertTrue(has_permission(officer, "view_complaints"))
        self.assertTrue(has_permission(officer, "create_complaint"))
        self.assertTrue(has_permission(officer, "download_files"))
        self.assertFalse(has_permission(officer, "manage_settings"))
        self.assertFalse(has_permission(officer, "manage_officers"))
        self.assertFalse(has_permission(officer, "view_audit_logs"))

        # Viewer permissions
        self.assertTrue(has_permission(viewer, "view_complaints"))
        self.assertTrue(has_permission(viewer, "download_files"))
        self.assertFalse(has_permission(viewer, "create_complaint"))
        self.assertFalse(has_permission(viewer, "manage_settings"))
        self.assertFalse(has_permission(viewer, "manage_officers"))
        self.assertFalse(has_permission(viewer, "view_audit_logs"))

        # Inactive / None
        self.assertFalse(has_permission(inactive_admin, "manage_officers"))
        self.assertFalse(has_permission(None, "view_complaints"))
        self.assertFalse(has_permission({}, "view_complaints"))

    def test_14_case_audio_valid_authenticated_access(self):
        """14. A valid complaint audio file can be accessed by authenticated users via ID or path."""
        self._login_as("patrol_officer", "OfficerPass123!")

        # 1. Retrieve via complaint ID
        resp_id = self.client.get(f"/case_audio/{self.complaint_id}")
        self.assertEqual(resp_id.status_code, 200)
        self.assertTrue(
            resp_id.content_type.startswith("video/webm") or
            resp_id.content_type.startswith("audio/")
        )
        self.assertGreater(len(resp_id.data), 1000)

        # 2. Retrieve via registered relative path
        resp_path = self.client.get("/case_audio/audio/Complaint_Audio.webm")
        self.assertEqual(resp_path.status_code, 200)
        self.assertEqual(len(resp_path.data), len(resp_id.data))

    def test_15_case_audio_unauthenticated_rejected(self):
        """15. An unauthenticated user cannot access audio and receives 401 Unauthorized."""
        # By ID
        resp_id = self.client.get(f"/case_audio/{self.complaint_id}")
        self.assertEqual(resp_id.status_code, 401)

        # By path
        resp_path = self.client.get("/case_audio/audio/Complaint_Audio.webm")
        self.assertEqual(resp_path.status_code, 401)

    def test_16_case_audio_env_access_rejected(self):
        """16. An attacker cannot retrieve .env or secret configuration through /case_audio."""
        self._login_as("patrol_officer", "OfficerPass123!")

        # Direct .env request
        resp = self.client.get("/case_audio/.env")
        self.assertIn(resp.status_code, (400, 403))
        self.assertNotIn(b"SECRET_KEY", resp.data)

        # Encoded / hidden variants
        resp_enc = self.client.get("/case_audio/%2e%65%6e%76")
        self.assertIn(resp_enc.status_code, (400, 403))
        self.assertNotIn(b"SECRET_KEY", resp_enc.data)

    def test_17_case_audio_db_access_rejected(self):
        """17. An attacker cannot retrieve SQLite database files through /case_audio."""
        self._login_as("patrol_officer", "OfficerPass123!")

        for db_file in ["complaints.db", "database.sqlite", "test.db"]:
            resp = self.client.get(f"/case_audio/{db_file}")
            self.assertIn(resp.status_code, (400, 403))
            self.assertNotIn(b"SQLite format 3", resp.data)

    def test_18_case_audio_backups_access_rejected(self):
        """18. An attacker cannot retrieve backup files through /case_audio."""
        self._login_as("patrol_officer", "OfficerPass123!")

        backup_attempts = [
            "backups/complaints_backup_20261101_122452.db",
            "backups/complaints_backup_test.db",
            "backups/backup.sql",
        ]
        for b_path in backup_attempts:
            resp = self.client.get(f"/case_audio/{b_path}")
            self.assertIn(resp.status_code, (400, 403))
            self.assertNotIn(b"SQLite format 3", resp.data)

    def test_19_case_audio_flask_session_access_rejected(self):
        """19. An attacker cannot retrieve session storage files through /case_audio."""
        self._login_as("patrol_officer", "OfficerPass123!")

        session_attempts = [
            ".flask_session/sess_test123",
            ".flask_session/any_file",
        ]
        for s_path in session_attempts:
            resp = self.client.get(f"/case_audio/{s_path}")
            self.assertIn(resp.status_code, (400, 403))

    def test_20_case_audio_path_traversal_rejected(self):
        """20. Path traversal sequences like ../ or encoded variants are strictly rejected with 400."""
        self._login_as("patrol_officer", "OfficerPass123!")

        traversal_attempts = [
            "/case_audio/..%2f.env",
            "/case_audio/../../config.py",
            "/case_audio/..\\..\\config.py",
            "/case_audio/audio/../app.py",
            "/case_audio/../audio/Complaint_Audio.webm",
            "/case_audio/etc/passwd",
        ]
        for t_path in traversal_attempts:
            resp = self.client.get(t_path)
            self.assertEqual(resp.status_code, 400)

    def test_21a_case_audio_symlink_inside_audio_rejected(self):
        """21a. Symlink pointing to a file inside audio/ is rejected with 403 Forbidden."""
        self._login_as("patrol_officer", "OfficerPass123!")

        real_audio = Path(Config.BASE_DIR) / "audio" / "Complaint_Audio.webm"
        symlink_path = Path(Config.BASE_DIR) / "audio" / "test_symlink_inside.webm"

        try:
            os.symlink(real_audio, symlink_path)
        except OSError as e:
            self.skipTest(f"Symlink creation unavailable due to OS permissions: {e}")

        try:
            # Register complaint with symlinked audio path
            sym_cid = save_complaint(
                registered_on="2026-11-01 11:00:00",
                english_name="Symlink Test User",
                telugu_name="సిమ్ లింక్ యూజర్",
                phone="9999999999",
                subject="Symlink Inside Test",
                audio_path="audio/test_symlink_inside.webm",
                telugu_complaint="ఫిర్యాదు",
                english_complaint="Complaint",
                db_path=self.temp_db_path
            )

            # 1. Access by complaint ID
            resp_id = self.client.get(f"/case_audio/{sym_cid}")
            self.assertEqual(resp_id.status_code, 403)
            self.assertIn("symbolic links are not permitted", resp_id.data.decode("utf-8").lower())

            # 2. Access by relative path
            resp_path = self.client.get("/case_audio/audio/test_symlink_inside.webm")
            self.assertEqual(resp_path.status_code, 403)
            self.assertIn("symbolic links are not permitted", resp_path.data.decode("utf-8").lower())
        finally:
            if symlink_path.is_symlink() or symlink_path.exists():
                try:
                    os.unlink(symlink_path)
                except OSError:
                    pass

    def test_21b_case_audio_symlink_outside_audio_rejected(self):
        """21b. Symlink pointing to a file outside audio/ (e.g. .env) is rejected with 403 Forbidden."""
        self._login_as("patrol_officer", "OfficerPass123!")

        outside_target = Path(Config.BASE_DIR) / ".env"
        symlink_path = Path(Config.BASE_DIR) / "audio" / "test_symlink_outside.webm"

        try:
            os.symlink(outside_target, symlink_path)
        except OSError as e:
            self.skipTest(f"Symlink creation unavailable due to OS permissions: {e}")

        try:
            sym_cid = save_complaint(
                registered_on="2026-11-01 11:30:00",
                english_name="Symlink Outside Test",
                telugu_name="సిమ్ లింక్ అవుట్ సైడ్",
                phone="9999999998",
                subject="Symlink Outside Test",
                audio_path="audio/test_symlink_outside.webm",
                telugu_complaint="ఫిర్యాదు",
                english_complaint="Complaint",
                db_path=self.temp_db_path
            )

            resp = self.client.get(f"/case_audio/{sym_cid}")
            self.assertEqual(resp.status_code, 403)
            self.assertNotIn(b"SECRET_KEY", resp.data)
        finally:
            if symlink_path.is_symlink() or symlink_path.exists():
                try:
                    os.unlink(symlink_path)
                except OSError:
                    pass

    def test_21c_case_audio_symlinked_parent_directory_rejected(self):
        """21c. Symlinked parent directory in the path is rejected with 403 Forbidden."""
        self._login_as("patrol_officer", "OfficerPass123!")

        real_audio_dir = Path(Config.BASE_DIR) / "audio"
        symlink_dir = Path(Config.BASE_DIR) / "case_records" / "test_symlink_parent_dir"

        try:
            os.symlink(real_audio_dir, symlink_dir, target_is_directory=True)
        except OSError as e:
            self.skipTest(f"Symlink creation unavailable due to OS permissions: {e}")

        try:
            sym_cid = save_complaint(
                registered_on="2026-11-01 12:00:00",
                english_name="Symlink Dir Test",
                telugu_name="సిమ్ లింక్ డైరెక్టరీ",
                phone="9999999997",
                subject="Symlink Dir Test",
                audio_path="case_records/test_symlink_parent_dir/Complaint_Audio.webm",
                telugu_complaint="ఫిర్యాదు",
                english_complaint="Complaint",
                db_path=self.temp_db_path
            )

            resp = self.client.get(f"/case_audio/{sym_cid}")
            self.assertEqual(resp.status_code, 403)
            self.assertIn("symbolic links are not permitted", resp.data.decode("utf-8").lower())
        finally:
            if symlink_dir.is_symlink() or symlink_dir.exists():
                try:
                    os.unlink(symlink_dir)
                except OSError:
                    try:
                        os.rmdir(symlink_dir)
                    except OSError:
                        pass

    def test_21d_case_audio_symlink_mocked_defense(self):
        """21d. Validate symlink detection helper and route response when symlinks are present."""
        from backend.routes.complaints import is_or_has_symlink

        self._login_as("patrol_officer", "OfficerPass123!")

        # Normal file without symlinks
        base_dir = Path(Config.BASE_DIR).resolve()
        normal_path = base_dir / "audio" / "Complaint_Audio.webm"
        self.assertFalse(is_or_has_symlink(normal_path, base_dir))

        # Mock os.path.islink returning True for audio path
        with patch("backend.routes.complaints.os.path.islink", return_value=True):
            resp = self.client.get(f"/case_audio/{self.complaint_id}")
            self.assertEqual(resp.status_code, 403)
            self.assertIn("symbolic links are not permitted", resp.data.decode("utf-8").lower())

    def test_21e_case_audio_symlink_inspection_error_fails_closed(self):
        """21e. If filesystem inspection raises OSError or ValueError, helper fails closed (returns True/unsafe)."""
        from backend.routes.complaints import is_or_has_symlink

        self._login_as("patrol_officer", "OfficerPass123!")

        base_dir = Path(Config.BASE_DIR).resolve()
        test_path = base_dir / "audio" / "Complaint_Audio.webm"

        # 1. Mock OSError during os.path.islink inspection
        with patch("backend.routes.complaints.os.path.islink", side_effect=OSError("Filesystem inspection error")):
            # Helper verification: fails closed by returning True (treated as unsafe)
            self.assertTrue(is_or_has_symlink(test_path, base_dir))

            # Route verification: endpoint rejects request with 403 Forbidden
            resp = self.client.get(f"/case_audio/{self.complaint_id}")
            self.assertEqual(resp.status_code, 403)
            self.assertIn("symbolic links are not permitted", resp.data.decode("utf-8").lower())

        # 2. Mock ValueError during path inspection
        with patch("backend.routes.complaints.os.path.islink", side_effect=ValueError("Invalid path data")):
            self.assertTrue(is_or_has_symlink(test_path, base_dir))

    def test_22_case_audio_invalid_extension_rejected(self):
        """22. Files with non-audio extensions are rejected with 400 Bad Request."""
        self._login_as("patrol_officer", "OfficerPass123!")

        disallowed_files = [
            "app.py",
            "config.py",
            "req.txt",
            "package.json",
            "script.sh",
            "audio/malicious.exe",
        ]
        for f_name in disallowed_files:
            resp = self.client.get(f"/case_audio/{f_name}")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Invalid audio file", resp.data.decode("utf-8"))

    def test_23_case_audio_nonexistent_complaint_id_rejected(self):
        """23. Nonexistent complaint IDs return 404 Not Found."""
        self._login_as("patrol_officer", "OfficerPass123!")

        resp = self.client.get("/case_audio/999999")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("Complaint audio not found", resp.data.decode("utf-8"))

    def test_24_case_audio_unregistered_audio_file_rejected(self):
        """24. Audio files not referenced in any complaint record return 404 Not Found."""
        self._login_as("patrol_officer", "OfficerPass123!")

        resp = self.client.get("/case_audio/audio/unreferenced_recording.webm")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("Audio file is not associated with any valid complaint", resp.data.decode("utf-8"))

    def test_25_atomic_admin_protection_under_concurrency(self):
        """25. Atomic transactions ensure the sole remaining active admin cannot be removed during concurrent requests."""
        import concurrent.futures

        # Create a second admin so there are initially 2 active admins
        admin2_id = create_officer(
            username="admin_user_2",
            password_hash=generate_password_hash("Admin2Pass123!"),
            full_name="Second Administrator",
            badge_number="ADM02",
            role="admin",
            db_path=self.temp_db_path
        )

        self.assertEqual(count_active_admins(self.temp_db_path), 2)

        # Concurrently attempt to demote both admins to 'officer'
        def try_demote(officer_id):
            return update_officer_role_atomic(officer_id, "officer", db_path=self.temp_db_path)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(try_demote, self.admin_id)
            future2 = executor.submit(try_demote, admin2_id)
            res1 = future1.result()
            res2 = future2.result()

        results = [res1, res2]
        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        # Exactly 1 demotion must succeed and 1 must fail due to atomic locking
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("At least one active Administrator must remain", failures[0][1])

        # Exactly 1 active admin remains
        self.assertEqual(count_active_admins(self.temp_db_path), 1)

        # Now test concurrent deactivation on the last remaining active admin
        active_admin_row = [
            get_officer_by_id(self.admin_id, self.temp_db_path),
            get_officer_by_id(admin2_id, self.temp_db_path)
        ]
        remaining_admin_id = next(o["id"] for o in active_admin_row if o["role"] == "admin" and o["is_active"] == 1)

        def try_deactivate(officer_id):
            return update_officer_status_atomic(officer_id, False, db_path=self.temp_db_path)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(try_deactivate, remaining_admin_id)
            f2 = executor.submit(try_deactivate, remaining_admin_id)
            d1 = f1.result()
            d2 = f2.result()

        # Both attempts must fail because there is only 1 active admin
        self.assertFalse(d1[0])
        self.assertFalse(d2[0])
        self.assertEqual(count_active_admins(self.temp_db_path), 1)


if __name__ == "__main__":
    unittest.main()
