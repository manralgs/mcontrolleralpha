import os
import json
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort

enhancements = Blueprint("enhancements", __name__)

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def ensure_tables():
    c = conn()
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        account_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        object_type TEXT,
        object_id TEXT,
        object_name TEXT,
        path TEXT,
        method TEXT,
        details TEXT,
        ip_address TEXT,
        result TEXT NOT NULL DEFAULT 'success'
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
    c.commit()
    c.close()

def current_user():
    account_id = session.get("account_id")
    if not account_id:
        return None
    c = conn()
    row = c.execute("SELECT * FROM accounts WHERE id=? AND active=1", (account_id,)).fetchone()
    c.close()
    return row

def require(permission):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            account = current_user()
            if not account:
                return redirect(url_for("login", next=request.path))
            roles = {
                "admin": {"view","manage_users","manage_computers","manage_groups","manage_updates","scan","archive","remote"},
                "operator": {"view","manage_computers","manage_groups","scan","archive","remote"},
                "viewer": {"view"},
            }
            if permission not in roles.get(account["role"], set()):
                return render_template("forbidden.html", permission=permission), 403
            return fn(*args, **kwargs)
        return wrapped
    return deco

def write_audit(action, object_type=None, object_id=None, object_name=None, details=None, result="success"):
    account = current_user()
    c = conn()
    c.execute("""INSERT INTO audit_log
        (created_at,account_id,username,action,object_type,object_id,object_name,path,method,details,ip_address,result)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(timespec="seconds"),
         account["id"] if account else None,
         account["username"] if account else None,
         action, object_type, str(object_id) if object_id is not None else None,
         object_name, request.path, request.method,
         json.dumps(details, ensure_ascii=False) if isinstance(details, (dict,list)) else details,
         request.headers.get("X-Forwarded-For", request.remote_addr),
         result))
    c.commit()
    c.close()

@enhancements.route("/operations")
@require("view")
def operations():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    os_name = request.args.get("os", "").strip()
    protocol = request.args.get("protocol", "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 25) or 25), 10), 100)
    where, params = [], []
    if q:
        where.append("(name LIKE ? OR address LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if status:
        where.append("status=?"); params.append(status)
    if os_name:
        where.append("os=?"); params.append(os_name)
    if protocol:
        where.append("protocol=?"); params.append(protocol)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    c = conn()
    total = c.execute("SELECT COUNT(*) n FROM computers" + clause, params).fetchone()["n"]
    rows = c.execute("SELECT * FROM computers" + clause + " ORDER BY name LIMIT ? OFFSET ?",
                     params + [per_page, (page-1)*per_page]).fetchall()
    statuses = [r["status"] for r in c.execute("SELECT DISTINCT status FROM computers WHERE status<>'' ORDER BY status")]
    oss = [r["os"] for r in c.execute("SELECT DISTINCT os FROM computers WHERE os<>'' ORDER BY os")]
    c.close()
    pages = max((total + per_page - 1)//per_page, 1)
    return render_template("operations.html", rows=rows, q=q, status=status, os_name=os_name,
                           protocol=protocol, page=page, pages=pages, total=total,
                           statuses=statuses, oss=oss, per_page=per_page)

@enhancements.route("/operations/computers/bulk-delete", methods=["POST"])
@require("manage_computers")
def bulk_delete_computers():
    ids = [int(x) for x in request.form.getlist("ids") if x.isdigit()]
    if not ids:
        flash("Select at least one computer.")
        return redirect(url_for("enhancements.operations"))
    c = conn()
    names = [r["name"] for r in c.execute(
        "SELECT name FROM computers WHERE id IN (%s)" % ",".join("?"*len(ids)), ids).fetchall()]
    c.execute("DELETE FROM computers WHERE id IN (%s)" % ",".join("?"*len(ids)), ids)
    c.commit(); c.close()
    write_audit("bulk_delete", "computer", details={"count":len(ids), "names":names})
    flash(f"Deleted {len(ids)} computer(s).")
    return redirect(url_for("enhancements.operations"))

@enhancements.route("/audit")
@require("view")
def audit():
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 50) or 50), 10), 100)
    action = request.args.get("action", "").strip()
    username = request.args.get("username", "").strip()
    q = request.args.get("q", "").strip()
    where, params = [], []
    if action:
        where.append("action=?"); params.append(action)
    if username:
        where.append("username=?"); params.append(username)
    if q:
        where.append("(object_name LIKE ? OR details LIKE ? OR path LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    c = conn()
    total = c.execute("SELECT COUNT(*) n FROM audit_log"+clause, params).fetchone()["n"]
    rows = c.execute("SELECT * FROM audit_log"+clause+" ORDER BY id DESC LIMIT ? OFFSET ?",
                     params+[per_page,(page-1)*per_page]).fetchall()
    actions = [r["action"] for r in c.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    users = [r["username"] for r in c.execute("SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY username")]
    c.close()
    pages = max((total+per_page-1)//per_page,1)
    return render_template("audit.html", rows=rows, actions=actions, users=users,
                           action=action, username=username, q=q, page=page, pages=pages, total=total)

def register_enhancements(app):
    ensure_tables()
    app.register_blueprint(enhancements)

    @app.after_request
    def audit_mutations(response):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path not in {"/login", "/setup"}:
            try:
                write_audit("request", details={"status_code":response.status_code}, result="success" if response.status_code < 400 else "failed")
            except Exception:
                pass
        return response
