import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

class MControllerScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        os.environ["MCONTROLLER_DB"] = str(self.db)
        os.environ["MCONTROLLER_SECRET_KEY"] = "test-secret-key"
        os.environ["MCONTROLLER_TESTING"] = "1"
        import app
        self.app_module = app
        self.app = app.app
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        app.DB = str(self.db)
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
        # The application creates the CSRF token through the template context.
        self.client.get("/scan")

    def _csrf(self):
        with self.client.session_transaction() as sess:
            return sess["_csrf"]

    def test_scan_page_exists(self):
        self._login()
        response = self.client.get("/scan")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Discover reachable computers", response.data)

    def test_scan_rejects_public_network(self):
        self._login()
        response = self.client.post("/scan", data={
            "_csrf": self._csrf(),
            "target": "8.8.8.0/24",
            "ports": "22",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"private IPv4", response.data)

    def test_scan_returns_open_endpoint(self):
        self._login()
        with patch.object(self.app_module, "probe_host", return_value=[22]):
            response = self.client.post("/scan", data={
                "_csrf": self._csrf(),
                "target": "192.168.1.10/32",
                "ports": "22,3389",
            })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"192.168.1.10", response.data)
        self.assertIn(b"SSH", response.data)

    def test_scan_add_creates_computer(self):
        self._login()
        response = self.client.post("/scan/add", data={
            "_csrf": self._csrf(),
            "address": "192.168.1.10",
            "protocol": "ssh",
            "port": "22",
            "name": "scan-test-host",
        })
        self.assertEqual(response.status_code, 302)
        c = sqlite3.connect(self.db)
        row = c.execute(
            "SELECT name,address,protocol,port,status FROM computers WHERE name=?",
            ("scan-test-host",),
        ).fetchone()
        c.close()
        self.assertEqual(row, ("scan-test-host", "192.168.1.10", "ssh", 22, "discovered"))

if __name__ == "__main__":
    unittest.main()
