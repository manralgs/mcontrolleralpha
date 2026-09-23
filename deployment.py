import os
import json
import sqlite3
import socket
import subprocess
import shlex
import shutil
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from urllib.parse import urlparse

deployment = Blueprint("deployment", __name__)
DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def _require(permission):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            account_id = session.get("account_id")
            if not account_id:
                return redirect(url_for("login", next=request.path))
            c = conn()
            account = c.execute("SELECT * FROM accounts WHERE id=? AND active=1", (account_id,)).fetchone()
            c.close()
            permissions = {
                "admin": {"view", "deploy"},
                "operator": {"view", "deploy"},
                "viewer": {"view"},
            }
            if not account or permission not in permissions.get(account["role"], set()):
                return render_template("forbidden.html", permission=permission), 403
            return fn(*args, **kwargs)
        return wrapped
    return deco

def _init():
    c = conn()
    c.execute("""CREATE TABLE IF NOT EXISTS deployment_jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        software_update_id INTEGER NOT NULL REFERENCES software_updates(id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        started_at TEXT,
        completed_at TEXT,
        detail TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS deployment_targets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL REFERENCES deployment_jobs(id) ON DELETE CASCADE,
        computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'queued',
        started_at TEXT,
        completed_at TEXT,
        detail TEXT,
        UNIQUE(job_id, computer_id)
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_deployment_jobs_status ON deployment_jobs(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_deployment_targets_job ON deployment_targets(job_id,status)")
    c.commit()
    c.close()

def _targets(c, target_type, target_ids):
    ids = [int(x) for x in target_ids if str(x).isdigit()]
    if not ids:
        return []
    if target_type == "computer":
        return c.execute(
            "SELECT * FROM computers WHERE id IN (%s) ORDER BY name" % ",".join("?" * len(ids)), ids
        ).fetchall()
    if target_type == "group":
        return c.execute(
            """SELECT DISTINCT c.* FROM computer_group_mappings gm
               JOIN mappings m ON m.id=gm.mapping_id
               JOIN computers c ON c.id=m.computer_id
               WHERE gm.group_id IN (%s) ORDER BY c.name""" % ",".join("?" * len(ids)), ids
        ).fetchall()
    return []


def _ssh_identity():
    key = os.environ.get("MCONTROLLER_SSH_KEY", "").strip()
    if not key:
        raise RuntimeError("MCONTROLLER_SSH_KEY is not configured.")
    path = os.path.abspath(os.path.expanduser(key))
    if not os.path.isfile(path):
        raise RuntimeError("Configured SSH key does not exist.")
    if shutil.which("ssh") is None:
        raise RuntimeError("OpenSSH client is not installed on the controller.")
    return path

def _mapped_username(c, computer_id):
    rows = c.execute("""SELECT u.username FROM mappings m
                        JOIN users u ON u.id=m.user_id
                        WHERE m.computer_id=? ORDER BY m.id""", (computer_id,)).fetchall()
    if len(rows) != 1:
        raise RuntimeError("Deployment requires exactly one remote-user mapping for the computer.")
    return rows[0]["username"]

def _ssh_command(address, port, username, command, key, timeout=60):
    target = f"{username}@{address}"
    return subprocess.run(
        ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "ConnectTimeout=10", "-p", str(int(port)), target, command],
        capture_output=True, text=True, timeout=timeout, check=False
    )

def _deploy_ssh(update, target, username):
    if target["os"].strip().lower() not in {"linux", "macos", "mac os", "darwin"}:
        raise RuntimeError("SSH deployment adapter currently supports Linux and macOS targets only.")
    if not update["package_url"]:
        raise RuntimeError("Software release has no package URL.")
    if not update["install_command"]:
        raise RuntimeError("Software release has no install command.")

    package_url = update["package_url"].strip()
    parsed = urlparse(package_url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise RuntimeError("Deployment package URL must use HTTPS.")
    filename = os.path.basename(parsed.path) or "package"
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise RuntimeError("Invalid deployment package filename.")

    key = _ssh_identity()
    token = secrets.token_hex(12)
    remote_dir = f"/tmp/mcontroller-deploy-{token}"
    package = remote_dir + "/" + filename
    expected_sha256 = ""
    try:
        expected_sha256 = str(update["sha256"] or "").strip().lower() if "sha256" in update.keys() else ""
    except (KeyError, TypeError):
        expected_sha256 = ""
    if expected_sha256 and (len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256)):
        raise RuntimeError("Software release SHA-256 must be a 64-character hexadecimal value.")

    def remote(command, timeout):
        return _ssh_command(target["address"], target["port"], username, command, key, timeout=timeout)

    try:
        prep = (
            "set -eu; umask 077; mkdir -p " + shlex.quote(remote_dir) +
            "; curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 " +
            shlex.quote(package_url) + " -o " + shlex.quote(package)
        )
        result = remote(prep, 120)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "Remote package download failed").strip()[-2000:])

        if expected_sha256:
            verify = remote(
                "set -eu; actual=$(sha256sum " + shlex.quote(package) +
                " | awk '{print $1}'); test \"$actual\" = " + shlex.quote(expected_sha256),
                60,
            )
            if verify.returncode != 0:
                raise RuntimeError("Remote package SHA-256 verification failed.")

        install = "set -eu; " + update["install_command"]
        install = install.replace("{package}", shlex.quote(package))
        install_result = remote(install, 600)
        if install_result.returncode != 0:
            raise RuntimeError((install_result.stderr or install_result.stdout or "Remote installation failed").strip()[-2000:])
        return (install_result.stdout or "Deployment completed.").strip()[-2000:]
    finally:
        try:
            cleanup = remote("rm -rf " + shlex.quote(remote_dir), 30)
            if cleanup.returncode != 0:
                raise RuntimeError((cleanup.stderr or cleanup.stdout or "Remote cleanup failed").strip()[-1000:])
        except Exception:
            # Preserve the original deployment exception while still making cleanup best-effort.
            pass

def _preflight_target(row, timeout=1.0):
    try:
        with socket.create_connection((row["address"], int(row["port"])), timeout=timeout):
            return "ready", f"TCP {row['address']}:{row['port']} reachable"
    except OSError as exc:
        return "failed", f"TCP preflight failed: {exc}"

@deployment.route("/deployment")
@_require("view")
def index():
    _init()
    c = conn()
    jobs = c.execute("""SELECT j.*,u.username,
                        s.name software,s.version,s.platform,
                        COUNT(t.id) target_count,
                        SUM(CASE WHEN t.status='ready' THEN 1 ELSE 0 END) ready_count,
                        SUM(CASE WHEN t.status='failed' THEN 1 ELSE 0 END) failed_count
                        FROM deployment_jobs j
                        JOIN software_updates s ON s.id=j.software_update_id
                        LEFT JOIN accounts u ON u.id=j.created_by
                        LEFT JOIN deployment_targets t ON t.job_id=j.id
                        GROUP BY j.id ORDER BY j.id DESC LIMIT 100""").fetchall()
    updates = c.execute("SELECT * FROM software_updates ORDER BY name,version DESC").fetchall()
    computers = c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    groups = c.execute("SELECT * FROM computer_groups ORDER BY name").fetchall()
    c.close()
    return render_template("deployment.html", jobs=jobs, updates=updates, computers=computers, groups=groups)

@deployment.route("/deployment/job", methods=["POST"])
@_require("deploy")
def create_job():
    _init()
    name = request.form.get("name", "").strip()
    update_id = request.form.get("software_update_id", "")
    target_type = request.form.get("target_type", "computer")
    target_ids = request.form.getlist("target_ids")
    if not name or not update_id.isdigit() or target_type not in {"computer", "group"} or not target_ids:
        flash("Deployment name, software release, and at least one target are required.")
        return redirect(url_for("deployment.index"))
    c = conn()
    update = c.execute("SELECT * FROM software_updates WHERE id=?", (int(update_id),)).fetchone()
    targets = _targets(c, target_type, target_ids) if update else []
    if not update:
        c.close()
        flash("Software release not found.")
        return redirect(url_for("deployment.index"))
    if not targets:
        c.close()
        flash("No valid deployment targets were selected.")
        return redirect(url_for("deployment.index"))
    now = datetime.now().isoformat(timespec="seconds")
    cur = c.execute("""INSERT INTO deployment_jobs
        (name,software_update_id,created_at,created_by,status,detail)
        VALUES(?,?,?,?,?,?)""",
        (name, update["id"], now, session.get("account_id"), "queued",
         "Created; awaiting preflight. Remote execution requires a configured deployment transport."))
    job_id = cur.lastrowid
    c.executemany("INSERT INTO deployment_targets(job_id,computer_id) VALUES(?,?)",
                  [(job_id, r["id"]) for r in targets])
    c.commit()
    c.close()
    flash(f"Deployment job #{job_id} created with {len(targets)} target(s). Run preflight before dispatch.")
    return redirect(url_for("deployment.job_detail", job_id=job_id))

@deployment.route("/deployment/job/<int:job_id>")
@_require("view")
def job_detail(job_id):
    _init()
    c = conn()
    job = c.execute("""SELECT j.*,s.name software,s.version,s.platform,s.package_url,s.install_command,
                       a.username FROM deployment_jobs j
                       JOIN software_updates s ON s.id=j.software_update_id
                       LEFT JOIN accounts a ON a.id=j.created_by WHERE j.id=?""", (job_id,)).fetchone()
    targets = c.execute("""SELECT t.*,c.name computer,c.address,c.protocol,c.port,c.os,c.status computer_status
                           FROM deployment_targets t JOIN computers c ON c.id=t.computer_id
                           WHERE t.job_id=? ORDER BY c.name""", (job_id,)).fetchall()
    c.close()
    if not job:
        abort(404)
    return render_template("deployment_job.html", job=job, targets=targets)

@deployment.route("/deployment/job/<int:job_id>/preflight", methods=["POST"])
@_require("deploy")
def preflight(job_id):
    _init()
    c = conn()
    job = c.execute("SELECT * FROM deployment_jobs WHERE id=?", (job_id,)).fetchone()
    targets = c.execute("""SELECT t.*,c.address,c.port FROM deployment_targets t
                           JOIN computers c ON c.id=t.computer_id WHERE t.job_id=?""", (job_id,)).fetchall()
    if not job:
        c.close()
        abort(404)
    now = datetime.now().isoformat(timespec="seconds")
    ready = failed = 0
    for target in targets:
        status, detail = _preflight_target(target)
        if status == "ready":
            ready += 1
        else:
            failed += 1
        c.execute("""UPDATE deployment_targets SET status=?,started_at=?,completed_at=?,detail=? WHERE id=?""",
                  (status, now, now, detail, target["id"]))
    status = "ready" if ready and not failed else ("failed" if failed and not ready else "partial")
    c.execute("UPDATE deployment_jobs SET status=?,started_at=?,completed_at=?,detail=? WHERE id=?",
              (status, now, now, json.dumps({"ready":ready,"failed":failed}),
               job_id))
    c.commit()
    c.close()
    flash(f"Preflight complete: {ready} reachable, {failed} failed.")
    return redirect(url_for("deployment.job_detail", job_id=job_id))


@deployment.route("/deployment/job/<int:job_id>/dispatch", methods=["POST"])
@_require("deploy")
def dispatch(job_id):
    _init()
    c = conn()
    job = c.execute("""SELECT j.*,s.name software,s.version,s.platform,s.package_url,s.install_command
                       FROM deployment_jobs j JOIN software_updates s ON s.id=j.software_update_id
                       WHERE j.id=?""", (job_id,)).fetchone()
    targets = c.execute("""SELECT t.*,c.name computer,c.address,c.protocol,c.port,c.os
                           FROM deployment_targets t JOIN computers c ON c.id=t.computer_id
                           WHERE t.job_id=? AND t.status='ready' ORDER BY c.name""", (job_id,)).fetchall()
    if not job:
        c.close()
        abort(404)
    if job["status"] not in {"ready", "partial"}:
        c.close()
        flash("Run preflight successfully before dispatch.")
        return redirect(url_for("deployment.job_detail", job_id=job_id))
    if job["platform"].strip().lower() not in {"linux", "macos"}:
        c.close()
        flash("Current transport supports Linux/macOS releases only.")
        return redirect(url_for("deployment.job_detail", job_id=job_id))
    now = datetime.now().isoformat(timespec="seconds")
    c.execute("UPDATE deployment_jobs SET status='running',started_at=?,detail=? WHERE id=?",
              (now, now, job_id))
    c.commit()
    for target in targets:
        started = datetime.now().isoformat(timespec="seconds")
        c.execute("UPDATE deployment_targets SET status='running',started_at=?,detail=? WHERE id=?",
                  (started, "Dispatching over SSH.", target["id"]))
        c.commit()
        try:
            username = _mapped_username(c, target["computer_id"])
            detail = _deploy_ssh(job, target, username)
            status = "completed"
        except Exception as exc:
            detail = str(exc)
            status = "failed"
        finished = datetime.now().isoformat(timespec="seconds")
        c.execute("UPDATE deployment_targets SET status=?,completed_at=?,detail=? WHERE id=?",
                  (status, finished, detail, target["id"]))
        c.commit()
    failed = c.execute("SELECT COUNT(*) n FROM deployment_targets WHERE job_id=? AND status='failed'",(job_id,)).fetchone()["n"]
    completed = c.execute("SELECT COUNT(*) n FROM deployment_targets WHERE job_id=? AND status='completed'",(job_id,)).fetchone()["n"]
    remaining = c.execute("SELECT COUNT(*) n FROM deployment_targets WHERE job_id=? AND status IN ('queued','ready','running')",(job_id,)).fetchone()["n"]
    final = "completed" if completed and not failed and not remaining else ("failed" if failed and not completed else "partial")
    c.execute("UPDATE deployment_jobs SET status=?,completed_at=?,detail=? WHERE id=?",
              (final, datetime.now().isoformat(timespec="seconds"),
               json.dumps({"completed":completed,"failed":failed,"remaining":remaining}), job_id))
    c.commit()
    c.close()
    flash(f"Deployment finished: {completed} completed, {failed} failed.")
    return redirect(url_for("deployment.job_detail", job_id=job_id))

@deployment.route("/deployment/job/<int:job_id>/cancel", methods=["POST"])
@_require("deploy")
def cancel(job_id):
    _init()
    c = conn()
    row = c.execute("SELECT status FROM deployment_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        c.close()
        abort(404)
    if row["status"] in {"completed", "cancelled"}:
        c.close()
        flash("Deployment job is already closed.")
        return redirect(url_for("deployment.job_detail", job_id=job_id))
    c.execute("UPDATE deployment_jobs SET status='cancelled',completed_at=? WHERE id=?",
              (datetime.now().isoformat(timespec="seconds"), job_id))
    c.execute("UPDATE deployment_targets SET status='cancelled',completed_at=? WHERE job_id=? AND status IN ('queued','ready','partial')",
              (datetime.now().isoformat(timespec="seconds"), job_id))
    c.commit()
    c.close()
    flash(f"Deployment job #{job_id} cancelled.")
    return redirect(url_for("deployment.job_detail", job_id=job_id))

def register_deployment(app):
    _init()
    app.register_blueprint(deployment)
