import os
import json
import sqlite3
import socket
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort

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
