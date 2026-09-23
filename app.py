from flask import Flask, jsonify, request, render_template, render_template_string, redirect, url_for, send_from_directory, abort, session, flash
from functools import wraps
import os
import sqlite3
import zipfile
import json
import shutil
import tempfile
import urllib.request
import sys
import threading
import time
import ipaddress
import socket
import secrets
import hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import hmac
import subprocess
from enhancements import register_enhancements
from deployment import register_deployment

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")
ARCHIVE_ROOT = Path(os.environ.get("MCONTROLLER_ARCHIVE_ROOT", "archives")).resolve()
app = Flask(__name__)
app.config["TESTING"] = os.environ.get("MCONTROLLER_TESTING", "0") == "1"
app.secret_key = os.environ.get("MCONTROLLER_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.config.update(SESSION_COOKIE_SECURE=os.environ.get("MCONTROLLER_SECURE_COOKIE","0")=="1")
SERVER_START_ID=secrets.token_hex(8)

@app.context_processor
def security_context():
    token=session.get("_csrf")
    if not token:
        token=secrets.token_urlsafe(32)
        session["_csrf"]=token
    return {"csrf_token":token}

@app.before_request
def csrf_protect():
    if request.method in ("POST","PUT","PATCH","DELETE") and request.endpoint not in ("login","setup"):
        expected=session.get("_csrf","")
        supplied=request.form.get("_csrf") or request.headers.get("X-CSRF-Token","")
        if not expected or not supplied or not hmac.compare_digest(expected,supplied): abort(400,description="Invalid CSRF token.")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="SAMEORIGIN"
    response.headers["Referrer-Policy"]="same-origin"
    response.headers["Content-Security-Policy"]="default-src self; frame-ancestors self"
    return response

ROLES = ("admin", "operator", "viewer")
ROLE_PERMISSIONS = {
    "admin": {"view", "manage_users", "manage_computers", "manage_groups", "manage_updates", "scan", "archive", "remote", "deploy"},
    "operator": {"view", "manage_computers", "manage_groups", "scan", "archive", "remote", "deploy"},
    "viewer": {"view"},
}

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS computers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,address TEXT NOT NULL,
      protocol TEXT NOT NULL DEFAULT 'rdp',port INTEGER NOT NULL DEFAULT 3389,
      os TEXT NOT NULL DEFAULT 'Windows',status TEXT NOT NULL DEFAULT 'unknown',
      last_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,display_name TEXT
    );
    CREATE TABLE IF NOT EXISTS mappings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,UNIQUE(computer_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS archives(
      id INTEGER PRIMARY KEY AUTOINCREMENT,source_path TEXT NOT NULL,zip_name TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,size INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS computer_groups(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,description TEXT
    );
    CREATE TABLE IF NOT EXISTS computer_group_mappings(
      group_id INTEGER NOT NULL REFERENCES computer_groups(id) ON DELETE CASCADE,
      mapping_id INTEGER NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
      PRIMARY KEY(group_id,mapping_id)
    );
    CREATE TABLE IF NOT EXISTS accounts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS software_updates(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,version TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'Windows',package_url TEXT,install_command TEXT,
      release_notes TEXT,created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS server_settings(
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    );
    """)
    # Lightweight schema migration for databases created by earlier mController builds.
    existing={row["name"] for row in c.execute("PRAGMA table_info(computers)").fetchall()}
    for column, definition in (("os", "TEXT NOT NULL DEFAULT 'Windows'"),("status", "TEXT NOT NULL DEFAULT 'unknown'"),("last_seen", "TEXT")):
        if column not in existing:
            c.execute(f"ALTER TABLE computers ADD COLUMN {column} {definition}")
    c.commit()
    return c

def validate_password_policy(password):
    if len(password) < 12: return "Password must be at least 12 characters."
    if not any(ch.isupper() for ch in password): return "Password must contain an uppercase letter."
    if not any(ch.islower() for ch in password): return "Password must contain a lowercase letter."
    if not any(ch.isdigit() for ch in password): return "Password must contain a digit."
    if not any(not ch.isalnum() for ch in password): return "Password must contain a special character."
    return None

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$%s$%s" % (salt.hex(), digest.hex())

def safe_next_url(value):
    if not value: return url_for("index")
    parsed=urlparse(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/"):
        return url_for("index")
    return value

def verify_password(password, encoded):
    try:
        scheme, rounds, salt, digest = encoded.split("$")
        if scheme != "pbkdf2_sha256": return False
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return secrets.compare_digest(check.hex(), digest)
    except (ValueError, TypeError):
        return False

def current_account():
    account_id = session.get("account_id")
    if not account_id: return None
    c=db(); row=c.execute("SELECT * FROM accounts WHERE id=? AND active=1",(account_id,)).fetchone(); c.close()
    return row

def permission_required(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            account=current_account()
            if not account:
                return redirect(url_for("login", next=request.path))
            if permission not in ROLE_PERMISSIONS.get(account["role"], set()):
                return render_template("forbidden.html", permission=permission), 403
            return fn(*args, **kwargs)
        return wrapped
    return decorator

@app.context_processor
def auth_context():
    a=current_account()
    return {"current_account": a, "setup_needed": account_count()==0}

@app.before_request
def enforce_auth():
    public = {"login", "setup", "healthz", "static"}
    if request.endpoint in public or request.path.startswith("/static/"):
        return
    if account_count()==0:
        return redirect(url_for("setup"))

def account_count():
    c=db(); n=c.execute("SELECT COUNT(*) n FROM accounts").fetchone()["n"]; c.close(); return n

def get_setting(key, default=""):
    c=db()
    row=c.execute("SELECT value FROM server_settings WHERE key=?",(key,)).fetchone()
    c.close()
    return row["value"] if row else default

def set_setting(key, value):
    c=db()
    c.execute("INSERT INTO server_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(key,str(value)))
    c.commit()
    c.close()

def public_server_settings():
    return {
        "guacamole_url": get_setting("guacamole_url", os.environ.get("GUACAMOLE_URL","http://localhost:8080/guacamole/")),
        "archive_root": get_setting("archive_root", os.environ.get("MCONTROLLER_ARCHIVE_ROOT","archives")),
        "http_port": get_setting("http_port", os.environ.get("PORT","5000")),
        "restart_command": get_setting("restart_command", os.environ.get("MCONTROLLER_RESTART_COMMAND","")),
    }

def export_payload(kind):
    c=db()
    if kind=="computers":
        data={"type":"mcontroller-computers","version":1,"items":[dict(r) for r in c.execute("SELECT name,address,protocol,port,os,status,last_seen FROM computers ORDER BY name")]}
    elif kind=="users":
        data={"type":"mcontroller-users","version":1,"items":[dict(r) for r in c.execute("SELECT username,display_name FROM users ORDER BY username")]}
    elif kind=="groups":
        groups=[]
        for g in c.execute("SELECT name,description FROM computer_groups ORDER BY name").fetchall():
            members=[]
            for r in c.execute("""SELECT c.name computer,u.username
                                  FROM computer_group_mappings gm
                                  JOIN mappings m ON m.id=gm.mapping_id
                                  JOIN computers c ON c.id=m.computer_id
                                  JOIN users u ON u.id=m.user_id
                                  WHERE gm.group_id=? ORDER BY c.name,u.username""",(g["id"],)).fetchall():
                members.append(dict(r))
            groups.append({"name":g["name"],"description":g["description"],"members":members})
        data={"type":"mcontroller-groups","version":1,"items":groups}
    else:
        raise ValueError("Unknown export type")
    c.close()
    return data

def import_payload(payload, kind):
    if not isinstance(payload,dict) or payload.get("version")!=1:
        raise ValueError("Unsupported import format.")
    expected={"computers":"mcontroller-computers","users":"mcontroller-users","groups":"mcontroller-groups"}[kind]
    if payload.get("type")!=expected or not isinstance(payload.get("items"),list):
        raise ValueError("Import file does not match the selected object type.")
    c=db()
    try:
        for item in payload["items"]:
            if kind=="computers":
                c.execute("""INSERT INTO computers(name,address,protocol,port,os,status,last_seen)
                            VALUES(?,?,?,?,?,?,?)
                            ON CONFLICT(name) DO UPDATE SET address=excluded.address,protocol=excluded.protocol,
                            port=excluded.port,os=excluded.os,status=excluded.status,last_seen=excluded.last_seen""",
                          (item["name"],item["address"],item.get("protocol","rdp"),int(item.get("port",3389)),
                           item.get("os","Windows"),item.get("status","unknown"),item.get("last_seen")))
            elif kind=="users":
                c.execute("""INSERT INTO users(username,display_name) VALUES(?,?)
                            ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name""",
                          (item["username"],item.get("display_name","")))
            else:
                c.execute("""INSERT INTO computer_groups(name,description) VALUES(?,?)
                            ON CONFLICT(name) DO UPDATE SET description=excluded.description""",
                          (item["name"],item.get("description","")))
                gid=c.execute("SELECT id FROM computer_groups WHERE name=?",(item["name"],)).fetchone()["id"]
                for member in item.get("members",[]):
                    comp=c.execute("SELECT id FROM computers WHERE name=?",(member.get("computer"),)).fetchone()
                    user=c.execute("SELECT id FROM users WHERE username=?",(member.get("username"),)).fetchone()
                    if not comp or not user:
                        continue
                    c.execute("INSERT OR IGNORE INTO mappings(computer_id,user_id) VALUES(?,?)",(comp["id"],user["id"]))
                    mapping=c.execute("SELECT id FROM mappings WHERE computer_id=? AND user_id=?",(comp["id"],user["id"])).fetchone()
                    c.execute("INSERT OR IGNORE INTO computer_group_mappings(group_id,mapping_id) VALUES(?,?)",(gid,mapping["id"]))
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def ensure_env_admin():
    if account_count() or not os.environ.get("MCONTROLLER_ADMIN_PASSWORD"):
        return
    username=os.environ.get("MCONTROLLER_ADMIN_USERNAME","admin").strip() or "admin"
    c=db()
    c.execute("INSERT OR IGNORE INTO accounts(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
              (username,hash_password(os.environ["MCONTROLLER_ADMIN_PASSWORD"]),"admin",1,datetime.now().isoformat(timespec="seconds")))
    c.commit(); c.close()

UPDATE_EXCLUDED_NAMES = {".git", ".venv", "__pycache__", "mcontroller.db", "archives", "runtime", ".env"}

def _validate_update_member(name):
    p=Path(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"Unsafe update path: {name}")
    if any(part in UPDATE_EXCLUDED_NAMES for part in p.parts):
        raise ValueError(f"Update package contains excluded runtime path: {name}")

UPDATE_MAX_PACKAGE_BYTES=250*1024*1024

def _update_sha256(path):
    digest=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()

def _validate_update_version(current,target):
    def parts(v): return tuple(int(x) if x.isdigit() else 0 for x in v.lstrip("v").split("."))
    return parts(target)>parts(current)

def _download_update_package(package_url):
    if not package_url:
        raise ValueError("Package URL is required.")
    parsed=urlparse(package_url)
    if parsed.scheme not in {"http","https"}:
        raise ValueError("Update package URL must use HTTP or HTTPS.")
    with urllib.request.urlopen(package_url, timeout=60) as response:
        data=response.read()
    if len(data) > 250 * 1024 * 1024:
        raise ValueError("Update package is larger than the 250 MB limit.")
    fd,path=tempfile.mkstemp(prefix="mcontroller-update-",suffix=".zip")
    os.close(fd)
    Path(path).write_bytes(data)
    return Path(path)

def _validate_update_package_file(package):
    if package.stat().st_size > UPDATE_MAX_PACKAGE_BYTES:
        raise ValueError("Update package exceeds the 250 MB limit.")
    digest=_update_sha256(package)
    expected=os.environ.get("MCONTROLLER_UPDATE_SHA256","").strip().lower()
    if expected and digest.lower()!=expected:
        raise ValueError("Update package SHA-256 does not match MCONTROLLER_UPDATE_SHA256.")
    return digest

def _stage_update(package_path):
    stage=Path(tempfile.mkdtemp(prefix="mcontroller-update-stage-"))
    try:
        with zipfile.ZipFile(package_path) as zf:
            total_uncompressed=0
            for member in zf.infolist():
                _validate_update_member(member.filename)
                total_uncompressed += member.file_size
                if total_uncompressed > 1024 * 1024 * 1024:
                    raise ValueError("Update package expands beyond the 1 GB limit.")
            zf.extractall(stage)
        root=stage
        if not (root/"app.py").is_file():
            candidates=[p for p in root.iterdir() if p.is_dir() and (p/"app.py").is_file()]
            if len(candidates)==1:
                root=candidates[0]
        if not (root/"app.py").is_file():
            raise ValueError("Update package must contain app.py.")
        return stage,root
    except Exception:
        shutil.rmtree(stage,ignore_errors=True)
        raise

def _create_update_backup(project):
    backup=Path(tempfile.mkdtemp(prefix="mcontroller-update-backup-"))
    for source in project.rglob("*"):
        relative=source.relative_to(project)
        if any(part in UPDATE_EXCLUDED_NAMES for part in relative.parts): continue
        target=backup/relative
        if source.is_dir(): target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
    return backup

def _restore_update_backup(project,backup):
    for source in backup.rglob("*"):
        relative=source.relative_to(backup)
        if any(part in UPDATE_EXCLUDED_NAMES for part in relative.parts): continue
        target=project/relative
        if source.is_file():
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)

def _update_health_check(project):
    check=project/"app.py"
    if not check.is_file(): return False
    try:
        compile(check.read_text(encoding="utf-8"),str(check),"exec")
        return True
    except Exception:
        return False

def _apply_update(root):
    project=Path(__file__).resolve().parent
    for source in root.rglob("*"):
        relative=source.relative_to(root)
        if any(part in UPDATE_EXCLUDED_NAMES for part in relative.parts):
            continue
        target=project/relative
        if source.is_dir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)

def _restart_server():
    time.sleep(0.75)
    command=os.environ.get("MCONTROLLER_RESTART_COMMAND","").strip()
    if command:
        os.system(command)
        return
    script=Path(__file__).resolve()
    os.execv(sys.executable,[sys.executable,str(script),*sys.argv[1:]])

def _start_update_watchdog(backup):
    project=Path(__file__).resolve().parent
    watchdog=project/"update_watchdog.py"
    if not watchdog.is_file():
        raise RuntimeError("Post-restart update watchdog is missing.")
    port=int(get_setting("http_port", os.environ.get("PORT","5000")))
    env=os.environ.copy()
    env["MCONTROLLER_UPDATE_BACKUP"]=str(backup)
    env["MCONTROLLER_UPDATE_PROJECT"]=str(project)
    env["MCONTROLLER_UPDATE_PORT"]=str(port)
    env["MCONTROLLER_UPDATE_COMMAND"]=os.environ.get("MCONTROLLER_RESTART_COMMAND","").strip()
    env["MCONTROLLER_UPDATE_OLD_START_ID"]=SERVER_START_ID
    subprocess.Popen([sys.executable,str(watchdog)],env=env,
                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                     start_new_session=True)

def perform_update(package_url):
    package=None
    stage=None
    backup=None
    project=Path(__file__).resolve().parent
    try:
        package=_download_update_package(package_url)
        _validate_update_package_file(package)
        stage,root=_stage_update(package)
        if not _update_health_check(root):
            raise RuntimeError("Update package failed Python syntax validation.")
        backup=_create_update_backup(project)
        _apply_update(root)
        if not _update_health_check(project):
            _restore_update_backup(project,backup)
            raise RuntimeError("Updated application failed health validation; rollback completed.")
        _start_update_watchdog(backup)
        threading.Thread(target=_restart_server,daemon=True).start()
        backup=None
        return True,"Update staged, validated, and applied. The server is restarting now; post-restart health verification is active."
    except Exception:
        raise
    finally:
        if package: package.unlink(missing_ok=True)
        if stage: shutil.rmtree(stage,ignore_errors=True)
        if backup: shutil.rmtree(backup,ignore_errors=True)

def safe_zip_name(name):
    return name.replace("/", "_").replace("\\", "_").replace(":", "_").replace("..", "_")

def create_zip_from_path(source):
    source=Path(source).expanduser().resolve()
    if not source.exists(): raise FileNotFoundError(f"Path does not exist: {source}")
    ARCHIVE_ROOT.mkdir(parents=True,exist_ok=True)
    target=ARCHIVE_ROOT/f"{safe_zip_name(source.name or 'root')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    with zipfile.ZipFile(target,"w",zipfile.ZIP_DEFLATED) as zf:
        if source.is_file(): zf.write(source,source.name)
        else:
            for p in source.rglob("*"):
                if p.is_file(): zf.write(p,p.relative_to(source.parent))
    return source,target

def probe_host(address, ports, timeout=0.35):
    open_ports=[]
    for port in ports:
        try:
            with socket.create_connection((address,port),timeout=timeout):
                open_ports.append(port)
        except OSError:
            pass
    return open_ports

def protocol_for_port(port):
    return {22:"ssh",3389:"rdp",5900:"vnc",5901:"vnc"}.get(port,"ssh")

@app.route("/setup", methods=["GET","POST"])
def setup():
    if account_count():
        return redirect(url_for("login"))
    error=None
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        confirm=request.form.get("confirm","")
        if len(username)<3:
            error="Username must be at least 3 characters."
        elif validate_password_policy(password):
            error=validate_password_policy(password)
        elif password!=confirm:
            error="Passwords do not match."
        else:
            c=db(); c.execute("INSERT INTO accounts(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                              (username,hash_password(password),"admin",1,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()
            return redirect(url_for("login"))
    return render_template("setup.html",error=error)

LOGIN_MAX_ATTEMPTS=int(os.environ.get("MCONTROLLER_LOGIN_MAX_ATTEMPTS","5"))
LOGIN_WINDOW_SECONDS=int(os.environ.get("MCONTROLLER_LOGIN_WINDOW_SECONDS","900"))
LOGIN_LOCKOUT_SECONDS=int(os.environ.get("MCONTROLLER_LOGIN_LOCKOUT_SECONDS","900"))
_login_attempts={}
_login_lock=threading.Lock()

def _login_key():
    return request.remote_addr or "unknown"

def _login_allowed():
    now=time.time(); key=_login_key()
    with _login_lock:
        state=_login_attempts.get(key)
        if not state: return True
        if now-state["first"]>LOGIN_WINDOW_SECONDS:
            _login_attempts.pop(key,None); return True
        return state.get("locked_until",0)<=now

def _record_login_failure():
    now=time.time(); key=_login_key()
    with _login_lock:
        state=_login_attempts.get(key)
        if not state or now-state["first"]>LOGIN_WINDOW_SECONDS:
            state={"first":now,"count":0,"locked_until":0}; _login_attempts[key]=state
        state["count"]+=1
        if state["count"]>=LOGIN_MAX_ATTEMPTS:
            state["locked_until"]=now+LOGIN_LOCKOUT_SECONDS

def _clear_login_failures():
    with _login_lock: _login_attempts.pop(_login_key(),None)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_account(): return redirect(request.args.get("next") or url_for("index"))
    error=None
    if not _login_allowed():
        return render_template("login.html",error="Too many failed attempts. Try again later.",next=request.args.get("next","")), 429
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        c=db(); row=c.execute("SELECT * FROM accounts WHERE username=? AND active=1",(username,)).fetchone(); c.close()
        if row and verify_password(password,row["password_hash"]):
            _clear_login_failures()
            session.clear()
            session.permanent=False
            session["account_id"]=row["id"]
            session["authenticated_at"]=datetime.now().isoformat(timespec="seconds")
            return redirect(safe_next_url(request.form.get("next") or request.args.get("next")))
        _record_login_failure()
        error="Invalid username or password."
    return render_template("login.html",error=error,next=request.args.get("next",""))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/healthz")
def healthz():
    return jsonify({"status":"ok","service":"mcontroller","start_id":SERVER_START_ID}), 200

@app.route("/")
@permission_required("view")
def index():
    c=db()
    counts={k:c.execute(f"SELECT COUNT(*) n FROM {k}").fetchone()["n"] for k in ("computers","users","mappings","archives","computer_groups","accounts","software_updates")}
    try:
        online=c.execute("SELECT COUNT(*) n FROM computers WHERE status='online'").fetchone()["n"]
        offline=c.execute("SELECT COUNT(*) n FROM computers WHERE status='offline'").fetchone()["n"]
        health={"online":online,"offline":offline,"unknown":max(counts["computers"]-online-offline,0)}
    except sqlite3.OperationalError:
        health={"online":0,"offline":0,"unknown":counts["computers"]}
    try: pending_discovery=c.execute("SELECT COUNT(*) n FROM discovery_results WHERE status='pending'").fetchone()["n"]
    except sqlite3.OperationalError: pending_discovery=0
    try:
        orphan_computers=c.execute("SELECT COUNT(*) n FROM computers c LEFT JOIN mappings m ON m.computer_id=c.id WHERE m.id IS NULL").fetchone()["n"]
        orphan_users=c.execute("SELECT COUNT(*) n FROM users u LEFT JOIN mappings m ON m.user_id=u.id WHERE m.id IS NULL").fetchone()["n"]
    except sqlite3.OperationalError: orphan_computers=orphan_users=0
    try: recent_connections=c.execute("SELECT COUNT(*) n FROM connection_history WHERE started_at >= datetime('now','-24 hours')").fetchone()["n"]
    except sqlite3.OperationalError: recent_connections=0
    c.close()
    return render_template("dashboard.html",counts=counts,health=health,pending_discovery=pending_discovery,
                           orphan_computers=orphan_computers,orphan_users=orphan_users,recent_connections=recent_connections)
@app.route("/archives", methods=["GET","POST"])
@permission_required("archive")
def archives():
    message=None
    error=False
    if request.method=="POST":
        source_path=request.form.get("source_path","").strip()
        try:
            source,target=create_zip_from_path(source_path)
            c=db()
            c.execute("INSERT INTO archives(source_path,zip_name,created_at,size) VALUES(?,?,?,?)",
                      (str(source),target.name,datetime.now().isoformat(timespec="seconds"),target.stat().st_size))
            c.commit()
            c.close()
            message=f"Created ZIP: <a href='/archive/{target.name}' target='_blank'>{target.name}</a>"
        except Exception as exc:
            error=True
            message=f"Archive failed: {exc}"
    c=db()
    rows=c.execute("SELECT * FROM archives ORDER BY id DESC").fetchall()
    c.close()
    return render_template("archives.html",rows=rows,archive_root=ARCHIVE_ROOT,message=message,error=error)

@app.route("/archives/<int:archive_id>/delete", methods=["POST"])
@permission_required("archive")
def archive_delete(archive_id):
    c=db()
    row=c.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
    if not row:
        c.close()
        abort(404)
    target=(ARCHIVE_ROOT/row["zip_name"]).resolve()
    root=ARCHIVE_ROOT.resolve()
    if target.parent != root or not target.is_file():
        c.close()
        abort(404)
    try:
        target.unlink()
        c.execute("DELETE FROM archives WHERE id=?", (archive_id,))
        c.commit()
    finally:
        c.close()
    flash("Archive deleted.")
    return redirect(url_for("archives"))

@app.route("/archive/<path:filename>")
@permission_required("archive")
def archive_file(filename):
    safe=Path(filename).name
    if safe!=filename: abort(404)
    target=ARCHIVE_ROOT/safe
    if not target.is_file(): abort(404)
    return send_from_directory(ARCHIVE_ROOT,safe,as_attachment=False)

@app.route("/data/<kind>/export")
@permission_required("manage_updates")
def data_export(kind):
    if kind not in {"computers","groups","users"}:
        abort(404)
    payload=export_payload(kind)
    response=jsonify(payload)
    response.headers["Content-Disposition"]=f"attachment; filename=mcontroller-{kind}.json"
    return response

@app.route("/data/<kind>/import",methods=["POST"])
@permission_required("manage_updates")
def data_import(kind):
    if kind not in {"computers","groups","users"}:
        abort(404)
    uploaded=request.files.get("file")
    if not uploaded:
        flash(f"Select a {kind} JSON file.")
        return redirect(url_for("settings"))
    try:
        payload=json.loads(uploaded.read().decode("utf-8"))
        import_payload(payload,kind)
        flash(f"{kind.title()} imported successfully.")
    except Exception as exc:
        flash(f"{kind.title()} import failed: {exc}")
    return redirect(url_for("settings"))

@app.route("/api/archives")
@permission_required("view")
def api_archives():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM archives ORDER BY id DESC")]; c.close()
    for r in rows: r["url"]=url_for("archive_file",filename=r["zip_name"],_external=False)
    return jsonify(rows)

@app.route("/api/computers")
@permission_required("view")
def api_computers():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM computers ORDER BY name")]; c.close(); return jsonify(rows)

@app.route("/api/users")
@permission_required("view")
def api_users():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM users ORDER BY username")]; c.close(); return jsonify(rows)

@app.route("/api/mappings")
@permission_required("view")
def api_mappings():
    c=db(); rows=[dict(r) for r in c.execute("SELECT m.id,c.name computer,c.address,c.protocol,c.os,u.username FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id")]; c.close(); return jsonify(rows)

@app.route("/api/groups")
@permission_required("view")
def api_groups():
    c=db()
    rows=[]
    for g in c.execute("SELECT * FROM computer_groups ORDER BY name").fetchall():
        rows.append({"id":g["id"],"name":g["name"],"description":g["description"],
                     "mappings":[dict(x) for x in c.execute("""SELECT m.id,c.name computer,c.address,c.protocol,c.os,u.username
                       FROM computer_group_mappings gm JOIN mappings m ON m.id=gm.mapping_id JOIN computers c ON c.id=m.computer_id
                       JOIN users u ON u.id=m.user_id WHERE gm.group_id=?""",(g["id"],)).fetchall()]})
    c.close(); return jsonify(rows)

register_enhancements(app)
register_deployment(app)

if __name__=="__main__":
    ensure_env_admin()
    db().close()
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=False)