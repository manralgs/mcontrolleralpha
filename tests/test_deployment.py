import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

class MControllerDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        os.environ["MCONTROLLER_DB"] = str(self.db)
        os.environ["MCONTROLLER_SECRET_KEY"] = "test-secret-key"
        os.environ["MCONTROLLER_TESTING"] = "1"
        os.environ["MCONTROLLER_SSH_KEY"] = str(Path(self.tmp.name) / "deploy.key")
        Path(os.environ["MCONTROLLER_SSH_KEY"]).write_text("test-key")
        import app
        import deployment
        self.app_module = app
        self.deployment_module = deployment
        self.app = app.app
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()
        app.DB = str(self.db)
        deployment.DB = str(self.db)
        app.db().close()

    def tearDown(self):
        self.tmp.cleanup()

    def _update(self, sha256=""):
        return {
            "package_url": "https://updates.example.test/app-1.2.3.tar.gz",
            "install_command": "sudo installer --package {package}",
            "platform": "Linux",
            "sha256": sha256,
        }

    def _target(self):
        return {
            "os": "Linux",
            "address": "10.0.0.10",
            "port": 22,
        }

    def _result(self, returncode=0, stdout="", stderr=""):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    def _login(self, role="admin"):
        password = "StrongPassword1!"
        response = self.client.post("/setup", data={
            "username": "admin",
            "password": password,
            "confirm": password,
        })
        self.assertEqual(response.status_code, 302)
        if role != "admin":
            c = sqlite3.connect(self.db)
            c.execute(
                "INSERT INTO accounts(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                (role, "test-hash", role, 1, datetime.now().isoformat(timespec="seconds")),
            )
            c.commit()
            c.close()
        if role == "admin":
            username = "admin"
            login_password = password
        else:
            username = role
            login_password = "unused"
        if role == "viewer":
            with self.client.session_transaction() as sess:
                db = sqlite3.connect(self.db)
                row = db.execute("SELECT id FROM accounts WHERE username=?", (username,)).fetchone()
                db.close()
                sess["account_id"] = row[0]
        else:
            response = self.client.post("/login", data={
                "username": username,
                "password": login_password,
            }, follow_redirects=False)
            self.assertEqual(response.status_code, 302)

    def test_non_https_package_url_is_rejected_before_ssh(self):
        import deployment
        update = self._update()
        update["package_url"] = "http://updates.example.test/app.tar.gz"
        with patch.object(deployment, "_ssh_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "must use HTTPS"):
                deployment._deploy_ssh(update, self._target(), "deploy")
        identity.assert_not_called()

    def test_invalid_sha256_is_rejected_before_ssh(self):
        import deployment
        update = self._update("not-a-sha")
        with patch.object(deployment, "_ssh_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "64-character hexadecimal"):
                deployment._deploy_ssh(update, self._target(), "deploy")
        identity.assert_not_called()

    def test_sha256_mismatch_blocks_install_and_still_cleans_up(self):
        import deployment
        update = self._update("a" * 64)
        calls = []

        def command(address, port, username, command, key, timeout=60):
            calls.append(command)
            if "curl --fail" in command:
                return self._result()
            if "sha256sum" in command:
                return self._result(1, stderr="hash mismatch")
            if command.startswith("rm -rf "):
                return self._result()
            return self._result()

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"),              patch.object(deployment, "_ssh_command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "SHA-256 verification failed"):
                deployment._deploy_ssh(update, self._target(), "deploy")

        self.assertEqual(len([c for c in calls if "curl --fail" in c]), 1)
        self.assertEqual(len([c for c in calls if "sha256sum" in c]), 1)
        self.assertFalse(any("installer --package" in c for c in calls))
        self.assertEqual(len([c for c in calls if c.startswith("rm -rf ")]), 1)

    def test_download_failure_cleans_up(self):
        import deployment
        calls = []

        def command(address, port, username, command, key, timeout=60):
            calls.append(command)
            if "curl --fail" in command:
                return self._result(1, stderr="download failed")
            return self._result()

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"),              patch.object(deployment, "_ssh_command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                deployment._deploy_ssh(self._update(), self._target(), "deploy")

        self.assertEqual(len([c for c in calls if c.startswith("rm -rf ")]), 1)

    def test_success_reports_cleanup_failure(self):
        import deployment
        calls = []

        def command(address, port, username, command, key, timeout=60):
            calls.append(command)
            if command.startswith("rm -rf "):
                return self._result(1, stderr="cleanup failed")
            return self._result(stdout="installed")

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"), \
             patch.object(deployment, "_ssh_command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                deployment._deploy_ssh(self._update(), self._target(), "deploy")

        self.assertEqual(len([c for c in calls if c.startswith("rm -rf ")]), 1)

    def test_install_failure_preserves_cleanup_failure_context(self):
        import deployment
        calls = []

        def command(address, port, username, command, key, timeout=60):
            calls.append(command)
            if "curl --fail" in command:
                return self._result()
            if command.startswith("set -eu; sudo installer"):
                return self._result(1, stderr="install failed")
            if command.startswith("rm -rf "):
                return self._result(1, stderr="cleanup failed")
            return self._result()

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"), \
             patch.object(deployment, "_ssh_command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "install failed.*cleanup failed"):
                deployment._deploy_ssh(self._update(), self._target(), "deploy")

        self.assertEqual(len([c for c in calls if c.startswith("rm -rf ")]), 1)

    def test_install_failure_cleans_up(self):
        import deployment
        calls = []

        def command(address, port, username, command, key, timeout=60):
            calls.append(command)
            if "curl --fail" in command:
                return self._result()
            if command.startswith("set -eu; sudo installer"):
                return self._result(1, stderr="install failed")
            if command.startswith("rm -rf "):
                return self._result()
            return self._result()

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"),              patch.object(deployment, "_ssh_command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "install failed"):
                deployment._deploy_ssh(self._update(), self._target(), "deploy")

        self.assertEqual(len([c for c in calls if c.startswith("rm -rf ")]), 1)

    def test_each_deployment_uses_a_unique_remote_directory(self):
        import deployment
        commands = []

        def command(address, port, username, command, key, timeout=60):
            commands.append(command)
            return self._result()

        with patch.object(deployment, "_ssh_identity", return_value="/tmp/key"),              patch.object(deployment, "_ssh_command", side_effect=command),              patch.object(deployment.secrets, "token_hex", side_effect=["111111111111111111111111", "222222222222222222222222"]):
            deployment._deploy_ssh(self._update(), self._target(), "deploy")
            deployment._deploy_ssh(self._update(), self._target(), "deploy")

        paths = set()
        for command_text in commands:
            if "/tmp/mcontroller-deploy-" in command_text:
                start = command_text.index("/tmp/mcontroller-deploy-")
                paths.add(command_text[start:start + len("/tmp/mcontroller-deploy-") + 24])
        self.assertIn("/tmp/mcontroller-deploy-111111111111111111111111", paths)
        self.assertIn("/tmp/mcontroller-deploy-222222222222222222222222", paths)

    def test_viewer_cannot_create_deployment(self):
        self._login("viewer")
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "test-csrf"
        response = self.client.post("/deployment/job", data={
            "_csrf": "test-csrf",
            "name": "Test deployment",
            "software_update_id": "1",
            "target_type": "computer",
            "target_ids": ["1"],
        })
        self.assertEqual(response.status_code, 403)
    def test_dispatch_passes_release_sha256_to_transport(self):
        import deployment
        self._login("admin")
        sha256 = "a" * 64
        c = sqlite3.connect(self.db)
        c.execute(
            "INSERT INTO software_updates(name,version,platform,package_url,install_command,release_notes,created_at,sha256) VALUES(?,?,?,?,?,?,?,?)",
            ("Test App", "1.2.3", "Linux", "https://updates.example.test/app.tar.gz",
             "sudo installer --package {package}", "", datetime.now().isoformat(timespec="seconds"), sha256),
        )
        update_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.execute(
            "INSERT INTO computers(name,address,protocol,port,os,status,last_seen) VALUES(?,?,?,?,?,?,?)",
            ("deploy-host", "10.0.0.10", "ssh", 22, "Linux", "ready", datetime.now().isoformat(timespec="seconds")),
        )
        computer_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.execute("INSERT INTO users(username,display_name) VALUES(?,?)", ("deploy", "Deploy User"))
        user_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.execute("INSERT INTO mappings(computer_id,user_id) VALUES(?,?)", (computer_id, user_id))
        c.execute(
            "INSERT INTO deployment_jobs(name,software_update_id,created_at,created_by,status,detail) VALUES(?,?,?,?,?,?)",
            ("Test deployment", update_id, datetime.now().isoformat(timespec="seconds"), 1, "ready", "preflight ok"),
        )
        job_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.execute(
            "INSERT INTO deployment_targets(job_id,computer_id,status) VALUES(?,?,?)",
            (job_id, computer_id, "ready"),
        )
        c.commit()
        c.close()

        with self.client.session_transaction() as sess:
            sess["_csrf"] = "test-csrf"

        with patch.object(deployment, "_deploy_ssh", return_value="ok") as deploy:
            response = self.client.post(
                f"/deployment/job/{job_id}/dispatch",
                data={"_csrf": "test-csrf"},
            )

        self.assertEqual(response.status_code, 302)
        deploy.assert_called_once()
        self.assertEqual(deploy.call_args.args[0]["sha256"], sha256)

    def test_deployment_post_without_csrf_is_rejected(self):
        self._login("admin")
        response = self.client.post("/deployment/job", data={
            "name": "Test deployment",
            "software_update_id": "1",
            "target_type": "computer",
            "target_ids": ["1"],
        })
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
