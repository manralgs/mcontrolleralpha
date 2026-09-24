import os
import sqlite3
import tempfile
import unittest
from pathlib import Path


class MControllerPlaybookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        os.environ["MCONTROLLER_DB"] = str(self.db)
        os.environ["MCONTROLLER_SECRET_KEY"] = "test-secret-key"
        os.environ["MCONTROLLER_TESTING"] = "1"
        os.environ["MCONTROLLER_BACKUP_ROOT"] = str(Path(self.tmp.name) / "backups")
        import app
        import enhancements
        self.app_module = app
        self.enhancements_module = enhancements
        self.app = app.app
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        app.DB = str(self.db)
        enhancements.DB = str(self.db)
        app.db().close()

    def tearDown(self):
        self.tmp.cleanup()

    def _login(self):
        password = "StrongPassword1!"
        response = self.client.post("/setup", data={
            "username": "admin",
            "password": password,
            "confirm": password,
        })
        self.assertEqual(response.status_code, 302)
        response = self.client.post("/login", data={
            "username": "admin",
            "password": password,
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.client.get("/")

    def _csrf(self):
        with self.client.session_transaction() as sess:
            return sess["_csrf"]

    def test_management_routes_are_registered_and_reachable(self):
        self._login()
        required = {
            "/computers",
            "/users",
            "/mappings",
            "/groups",
            "/admin/users",
            "/settings",
            "/guacamole/<int:mapping_id>",
            "/discovery",
            "/health",
            "/connections",
            "/backup",
        }
        registered = {rule.rule for rule in self.app.url_map.iter_rules()}
        self.assertTrue(required.issubset(registered))

        for path in (
            "/computers",
            "/users",
            "/mappings",
            "/groups",
            "/admin/users",
            "/settings",
            "/discovery",
            "/health",
            "/connections",
            "/backup",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_logout_requires_post_and_csrf(self):
        self._login()
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 405)

        response = self.client.post("/logout", data={})
        self.assertEqual(response.status_code, 400)

        csrf = self._csrf()
        response = self.client.post("/logout", data={"_csrf": csrf})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_logged_in_login_next_is_local_only(self):
        self._login()
        response = self.client.get("/login?next=https://example.com", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_security_headers_use_valid_self_keyword(self):
        self._login()
        response = self.client.get("/")
        self.assertEqual(
            response.headers.get("Content-Security-Policy"),
            "default-src 'self'; frame-ancestors 'self'",
        )

    def test_discovery_scheduler_starts(self):
        self.assertTrue(getattr(self.app, "_discovery_scheduler_started", False))

    def test_settings_persist_and_validate_port(self):
        self._login()
        csrf = self._csrf()
        response = self.client.post("/settings", data={
            "_csrf": csrf,
            "guacamole_url": "http://localhost:8080/guacamole/",
            "archive_root": "archives-test",
            "http_port": "5123",
            "restart_command": "echo restart",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        c = sqlite3.connect(self.db)
        values = dict(c.execute("SELECT key,value FROM server_settings").fetchall())
        c.close()
        self.assertEqual(values["http_port"], "5123")
        self.assertEqual(values["archive_root"], "archives-test")

        csrf = self._csrf()
        response = self.client.post("/settings", data={
            "_csrf": csrf,
            "http_port": "99999",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        c = sqlite3.connect(self.db)
        value = c.execute("SELECT value FROM server_settings WHERE key='http_port'").fetchone()[0]
        c.close()
        self.assertEqual(value, "5123")


if __name__ == "__main__":
    unittest.main()
