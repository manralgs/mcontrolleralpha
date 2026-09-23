import os
import tempfile
import unittest
from pathlib import Path

class MControllerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        os.environ["MCONTROLLER_DB"] = str(self.db)
        os.environ["MCONTROLLER_SECRET_KEY"] = "test-secret-key"
        import app
        self.app = app.app
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()
        app.db().close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_healthz_is_public_and_returns_start_id(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["start_id"])

    def test_setup_requires_strong_password(self):
        response = self.client.post("/setup", data={
            "username": "admin",
            "password": "weakpassword",
            "confirm": "weakpassword",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"uppercase", response.data.lower())

    def test_setup_and_login(self):
        response = self.client.post("/setup", data={
            "username": "admin",
            "password": "StrongPassword1!",
            "confirm": "StrongPassword1!",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        response = self.client.post("/login", data={
            "username": "admin",
            "password": "StrongPassword1!",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_post_without_csrf_is_rejected(self):
        self.client.post("/setup", data={
            "username": "admin",
            "password": "StrongPassword1!",
            "confirm": "StrongPassword1!",
        })
        response = self.client.post("/computers", data={
            "name": "test",
            "address": "127.0.0.1",
            "protocol": "ssh",
            "port": "22",
            "os": "Linux",
        })
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
