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

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")
ARCHIVE_ROOT = Path(os.environ.get("MCONTROLLER_ARCHIVE_ROOT", "archives")).resolve()
app = Flask(__name__)
app.secret_key = os.environ.get("MCONTROLLER_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

ROLES = ("admin", "operator", "viewer")
ROLE_PERMISSIONS = {
    "admin": {"view", "manage_users", "manage_computers", "manage_groups", "manage_updates", "scan", "archive", "remote"},
    "operator": {"view", "manage_computers", "manage_groups", "scan", "archive", "remote"},
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
    public = {"login", "setup", "static"}
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

def perform_update(package_url):
    package=None
    stage=None
    try:
        package=_download_update_package(package_url)
        stage,root=_stage_update(package)
        _apply_update(root)
        threading.Thread(target=_restart_server,daemon=True).start()
        return True,"Update applied. The server is restarting now."
    finally:
        if package:
            package.unlink(missing_ok=True)
        if stage:
            shutil.rmtree(stage,ignore_errors=True)

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
        if len(username)<3 or len(password)<10:
            error="Username must be at least 3 characters and password at least 10 characters."
        elif password!=confirm:
            error="Passwords do not match."
        else:
            c=db(); c.execute("INSERT INTO accounts(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                              (username,hash_password(password),"admin",1,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()
            return redirect(url_for("login"))
    return render_template("setup.html",error=error)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_account(): return redirect(request.args.get("next") or url_for("index"))
    error=None
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        c=db(); row=c.execute("SELECT * FROM accounts WHERE username=? AND active=1",(username,)).fetchone(); c.close()
        if row and verify_password(password,row["password_hash"]):
            session.clear(); session["account_id"]=row["id"]
            return redirect(safe_next_url(request.form.get("next") or request.args.get("next")))
        error="Invalid username or password."
    return render_template("login.html",error=error,next=request.args.get("next",""))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@permission_required("view")
def index():
    c=db()
    counts={k:c.execute(f"SELECT COUNT(*) n FROM {k}").fetchone()["n"] for k in ("computers","users","mappings","archives","computer_groups","accounts","software_updates")}
    c.close()
    return render_template("dashboard.html",counts=counts)

@app.route("/computers",methods=["GET","POST"])
@permission_required("manage_computers")
def computers():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO computers(name,address,protocol,port,os,status) VALUES(?,?,?,?,?,?)",
                      (request.form["name"],request.form["address"],request.form.get("protocol","rdp"),
                       int(request.form.get("port",3389)),request.form.get("os","Windows"),"unknown")); c.commit()
        except (sqlite3.IntegrityError,ValueError): pass
        return redirect(url_for("computers"))
    rows=c.execute("SELECT * FROM computers ORDER BY name").fetchall(); c.close()
    return render_template("computers.html",rows=rows)

@app.route("/users",methods=["GET","POST"])
@permission_required("manage_users")
def users():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO users(username,display_name) VALUES(?,?)",
                      (request.form["username"],request.form.get("display_name",""))); c.commit()
        except sqlite3.IntegrityError: pass
        return redirect(url_for("users"))
    rows=c.execute("SELECT * FROM users ORDER BY username").fetchall(); c.close()
    return render_template("users.html",rows=rows)

@app.route("/mappings",methods=["GET","POST"])
@permission_required("manage_computers")
def mappings():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO mappings(computer_id,user_id) VALUES(?,?)",(request.form["computer_id"],request.form["user_id"])); c.commit()
        except sqlite3.IntegrityError: pass
        return redirect(url_for("mappings"))
    computers=c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    users=c.execute("SELECT * FROM users ORDER BY username").fetchall()
    rows=c.execute("SELECT m.id,m.computer_id,m.user_id,c.name,c.address,c.protocol,c.os,u.username FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id ORDER BY c.name,u.username").fetchall()
    c.close()
    return render_template("mappings.html",computers=computers,users=users,rows=rows)

@app.route("/groups",methods=["GET","POST"])
@permission_required("manage_groups")
def groups():
    c=db()
    if request.method=="POST":
        name=request.form.get("name","").strip()
        if name:
            try:
                c.execute("INSERT INTO computer_groups(name,description) VALUES(?,?)",(name,request.form.get("description","").strip())); c.commit()
            except sqlite3.IntegrityError: pass
        return redirect(url_for("groups"))
    groups=[]
    for g in c.execute("SELECT * FROM computer_groups ORDER BY name").fetchall():
        computers=c.execute("""SELECT m.id,c.name,c.address,c.protocol,c.os,u.username
                              FROM computer_group_mappings gm JOIN mappings m ON m.id=gm.mapping_id
                              JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                              WHERE gm.group_id=? ORDER BY c.name,u.username""",(g["id"],)).fetchall()
        groups.append(dict(g,computer_count=len(computers),computers=computers))
    available=c.execute("""SELECT m.id,c.name,c.address,c.protocol,c.os,u.username
                           FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                           ORDER BY c.name,u.username""").fetchall()
    c.close()
    return render_template("groups.html",groups=groups,available=available)

@app.route("/groups/<int:group_id>/add",methods=["POST"])
@permission_required("manage_groups")
def group_add(group_id):
    c=db()
    try:
        c.execute("INSERT INTO computer_group_mappings(group_id,mapping_id) VALUES(?,?)",(group_id,request.form["mapping_id"])); c.commit()
    except sqlite3.IntegrityError: pass
    c.close(); return redirect(url_for("groups"))

@app.route("/groups/<int:group_id>/remove/<int:mapping_id>",methods=["POST"])
@permission_required("manage_groups")
def group_remove(group_id,mapping_id):
    c=db(); c.execute("DELETE FROM computer_group_mappings WHERE group_id=? AND mapping_id=?",(group_id,mapping_id)); c.commit(); c.close()
    return redirect(url_for("groups"))

@app.route("/scan",methods=["GET","POST"])
@permission_required("scan")
def scan():
    results=[]; error=None
    if request.method=="POST":
        target=request.form.get("target","").strip()
        try:
            net=ipaddress.ip_network(target,strict=False)
            if net.version!=4 or net.prefixlen<16 or not net.is_private:
                raise ValueError("Use an IPv4 private subnet from /16 to /32.")
            ports=[]
            for raw in request.form.get("ports","22,3389,5900").split(","):
                p=int(raw.strip())
                if 1<=p<=65535: ports.append(p)
            if len(list(net.hosts()))>1024: raise ValueError("Scan is limited to 1024 addresses per request.")
            for ip in net.hosts():
                opened=probe_host(str(ip),ports)
                if opened: results.append({"address":str(ip),"ports":opened,"protocol":protocol_for_port(opened[0])})
        except ValueError as exc: error=str(exc)
    return render_template("scan.html",results=results,error=error)

@app.route("/scan/add",methods=["POST"])
@permission_required("manage_computers")
def scan_add():
    address=request.form["address"]; protocol=request.form.get("protocol","ssh"); port=int(request.form.get("port",22))
    name=request.form.get("name",address)
    c=db()
    try:
        c.execute("INSERT INTO computers(name,address,protocol,port,os,status) VALUES(?,?,?,?,?,?)",
                  (name,address,protocol,port,request.form.get("os","Unknown"),"discovered")); c.commit()
    except sqlite3.IntegrityError: pass
    c.close(); return redirect(url_for("computers"))

@app.route("/admin/users",methods=["GET","POST"])
@permission_required("manage_users")
def admin_users():
    c=db()
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        role=request.form.get("role","viewer")
        if username and len(password)>=10 and role in ROLES:
            try:
                c.execute("INSERT INTO accounts(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                          (username,hash_password(password),role,1,datetime.now().isoformat(timespec="seconds"))); c.commit()
            except sqlite3.IntegrityError: pass
        return redirect(url_for("admin_users"))
    rows=c.execute("SELECT id,username,role,active,created_at FROM accounts ORDER BY username").fetchall(); c.close()
    return render_template("admin_users.html",rows=rows,roles=ROLES)

@app.route("/admin/users/<int:account_id>/role",methods=["POST"])
@permission_required("manage_users")
def admin_user_role(account_id):
    role=request.form.get("role")
    if role in ROLES:
        c=db(); c.execute("UPDATE accounts SET role=? WHERE id=?",(role,account_id)); c.commit(); c.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:account_id>/delete",methods=["POST"])
@permission_required("manage_users")
def admin_user_delete(account_id):
    me=current_account()
    if me and me["id"]==account_id: return redirect(url_for("admin_users"))
    c=db()
    row=c.execute("SELECT role FROM accounts WHERE id=?",(account_id,)).fetchone()
    if row and row["role"]=="admin":
        admins=c.execute("SELECT COUNT(*) n FROM accounts WHERE role='admin' AND active=1").fetchone()["n"]
        if admins<=1:
            c.close(); return redirect(url_for("admin_users"))
    c.execute("DELETE FROM accounts WHERE id=?",(account_id,)); c.commit(); c.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:account_id>/toggle",methods=["POST"])
@permission_required("manage_users")
def admin_user_toggle(account_id):
    me=current_account()
    if me and me["id"]==account_id: return redirect(url_for("admin_users"))
    c=db(); c.execute("UPDATE accounts SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?",(account_id,)); c.commit(); c.close()
    return redirect(url_for("admin_users"))

@app.route("/settings",methods=["GET","POST"])
@permission_required("manage_updates")
def settings():
    global ARCHIVE_ROOT
    if request.method=="POST":
        archive_root=request.form.get("archive_root","").strip() or "archives"
        try:
            port=int(request.form.get("http_port","5000").strip() or "5000")
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            flash("HTTP port must be between 1 and 65535.")
            return redirect(url_for("settings"))
        set_setting("guacamole_url",request.form.get("guacamole_url","").strip())
        set_setting("archive_root",archive_root)
        set_setting("http_port",str(port))
        set_setting("restart_command",request.form.get("restart_command","").strip())
        ARCHIVE_ROOT=Path(archive_root).expanduser().resolve()
        flash("Server settings saved. HTTP port changes take effect after restart.")
        return redirect(url_for("settings"))
    return render_template("settings.html",settings=public_server_settings())

@app.route("/settings/export")
@permission_required("manage_updates")
def settings_export():
    payload={"type":"mcontroller-server-settings","version":1,"settings":public_server_settings()}
    response=jsonify(payload)
    response.headers["Content-Disposition"]="attachment; filename=mcontroller-server-settings.json"
    return response

@app.route("/settings/import",methods=["POST"])
@permission_required("manage_updates")
def settings_import():
    global ARCHIVE_ROOT
    uploaded=request.files.get("file")
    if not uploaded:
        flash("Select a settings JSON file.")
        return redirect(url_for("settings"))
    try:
        payload=json.loads(uploaded.read().decode("utf-8"))
        if payload.get("type")!="mcontroller-server-settings" or payload.get("version")!=1:
            raise ValueError("Unsupported server settings file.")
        values=payload.get("settings",{})
        for key in ("guacamole_url","archive_root","http_port","restart_command"):
            if key in values:
                set_setting(key,values[key])
        archive_value=get_setting("archive_root","archives")
        ARCHIVE_ROOT=Path(archive_value).expanduser().resolve()
        flash("Server settings imported. HTTP port changes take effect after restart.")
    except Exception as exc:
        flash(f"Settings import failed: {exc}")
    return redirect(url_for("settings"))

@app.route("/updates",methods=["GET","POST"])
@permission_required("manage_updates")
def updates():
    c=db()
    if request.method=="POST":
        c.execute("""INSERT INTO software_updates(name,version,platform,package_url,install_command,release_notes,created_at)
                     VALUES(?,?,?,?,?,?,?)""",
                  (request.form["name"],request.form["version"],request.form.get("platform","Windows"),
                   request.form.get("package_url",""),request.form.get("install_command",""),
                   request.form.get("release_notes",""),datetime.now().isoformat(timespec="seconds"))); c.commit()
        return redirect(url_for("updates"))
    rows=c.execute("SELECT * FROM software_updates ORDER BY id DESC").fetchall(); c.close()
    return render_template("updates.html",rows=rows)


# ---- CRUD operations for managed objects ----
@app.route("/computers/<int:item_id>/update",methods=["POST"])
@permission_required("manage_computers")
def computer_update(item_id):
    c=db()
    try: c.execute("UPDATE computers SET name=?,address=?,os=?,protocol=?,port=? WHERE id=?",(request.form["name"],request.form["address"],request.form.get("os","Unknown"),request.form.get("protocol","ssh"),int(request.form.get("port",22)),item_id)); c.commit()
    except (sqlite3.IntegrityError,ValueError): pass
    c.close(); return redirect(url_for("computers"))

@app.route("/computers/<int:item_id>/delete",methods=["POST"])
@permission_required("manage_computers")
def computer_delete(item_id):
    c=db(); c.execute("DELETE FROM computers WHERE id=?",(item_id,)); c.commit(); c.close(); return redirect(url_for("computers"))

@app.route("/users/<int:item_id>/update",methods=["POST"])
@permission_required("manage_users")
def user_update(item_id):
    c=db()
    try: c.execute("UPDATE users SET username=?,display_name=? WHERE id=?",(request.form["username"],request.form.get("display_name",""),item_id)); c.commit()
    except sqlite3.IntegrityError: pass
    c.close(); return redirect(url_for("users"))

@app.route("/users/<int:item_id>/delete",methods=["POST"])
@permission_required("manage_users")
def user_delete(item_id):
    c=db(); c.execute("DELETE FROM users WHERE id=?",(item_id,)); c.commit(); c.close(); return redirect(url_for("users"))

@app.route("/mappings/<int:item_id>/update",methods=["POST"])
@permission_required("manage_computers")
def mapping_update(item_id):
    c=db()
    try: c.execute("UPDATE mappings SET computer_id=?,user_id=? WHERE id=?",(request.form["computer_id"],request.form["user_id"],item_id)); c.commit()
    except sqlite3.IntegrityError: pass
    c.close(); return redirect(url_for("mappings"))

@app.route("/mappings/<int:item_id>/delete",methods=["POST"])
@permission_required("manage_computers")
def mapping_delete(item_id):
    c=db(); c.execute("DELETE FROM mappings WHERE id=?",(item_id,)); c.commit(); c.close(); return redirect(url_for("mappings"))

@app.route("/groups/<int:item_id>/update",methods=["POST"])
@permission_required("manage_groups")
def group_update(item_id):
    c=db()
    try: c.execute("UPDATE computer_groups SET name=?,description=? WHERE id=?",(request.form["name"],request.form.get("description",""),item_id)); c.commit()
    except sqlite3.IntegrityError: pass
    c.close(); return redirect(url_for("groups"))

@app.route("/groups/<int:item_id>/delete",methods=["POST"])
@permission_required("manage_groups")
def group_delete(item_id):
    c=db(); c.execute("DELETE FROM computer_groups WHERE id=?",(item_id,)); c.commit(); c.close(); return redirect(url_for("groups"))

@app.route("/admin/users/<int:account_id>/update",methods=["POST"])
@permission_required("manage_users")
def admin_user_update(account_id):
    role=request.form.get("role"); password=request.form.get("password","")
    if role in ROLES:
        c=db()
        if password: c.execute("UPDATE accounts SET username=?,role=?,password_hash=? WHERE id=?",(request.form["username"],role,hash_password(password),account_id))
        else: c.execute("UPDATE accounts SET username=?,role=? WHERE id=?",(request.form["username"],role,account_id))
        c.commit(); c.close()
    return redirect(url_for("admin_users"))

@app.route("/updates/<int:item_id>/update",methods=["POST"])
@permission_required("manage_updates")
def update_release(item_id):
    c=db(); c.execute("UPDATE software_updates SET name=?,version=?,platform=?,package_url=?,install_command=?,release_notes=? WHERE id=?",(request.form["name"],request.form["version"],request.form.get("platform","Windows"),request.form.get("package_url",""),request.form.get("install_command",""),request.form.get("release_notes",""),item_id)); c.commit(); c.close(); return redirect(url_for("updates"))

@app.route("/updates/<int:item_id>/delete",methods=["POST"])
@permission_required("manage_updates")
def delete_release(item_id):
    c=db(); c.execute("DELETE FROM software_updates WHERE id=?",(item_id,)); c.commit(); c.close(); return redirect(url_for("updates"))

@app.route("/updates/<int:item_id>/apply",methods=["POST"])
@permission_required("manage_updates")
def apply_release(item_id):
    c=db(); row=c.execute("SELECT * FROM software_updates WHERE id=?",(item_id,)).fetchone(); c.close()
    if not row:
        flash("Update release not found.")
        return redirect(url_for("updates"))
    try:
        perform_update(row["package_url"])
        flash("Update applied. The server is restarting now.")
    except Exception as exc:
        flash(f"Update failed: {exc}")
    return redirect(url_for("updates"))


@app.route("/archives/<int:item_id>/delete",methods=["POST"])
@permission_required("archive")
def archive_delete(item_id):
    c=db(); row=c.execute("SELECT zip_name FROM archives WHERE id=?",(item_id,)).fetchone()
    if row:
        target=ARCHIVE_ROOT/Path(row["zip_name"]).name
        if target.is_file(): target.unlink()
        c.execute("DELETE FROM archives WHERE id=?",(item_id,)); c.commit()
    c.close(); return redirect(url_for("archives"))

@app.route("/guacamole/<int:mapping_id>")
@permission_required("remote")
def guacamole(mapping_id):
    c=db(); r=c.execute("""SELECT c.*,u.username FROM mappings m JOIN computers c ON c.id=m.computer_id
                           JOIN users u ON u.id=m.user_id WHERE m.id=?""",(mapping_id,)).fetchone(); c.close()
    if not r: return "Mapping not found",404
    base=get_setting("guacamole_url", os.environ.get("GUACAMOLE_URL","http://localhost:8080/guacamole/"))
    return render_template("guacamole.html",r=r,base=base)

@app.route("/archives",methods=["GET","POST"])
@permission_required("archive")
def archives():
    message=""; error=False
    if request.method=="POST":
        try:
            source_path,target=create_zip_from_path(request.form.get("source_path","").strip())
            c=db(); c.execute("INSERT INTO archives(source_path,zip_name,created_at,size) VALUES(?,?,?,?)",
                              (str(source_path),target.name,datetime.now().isoformat(timespec="seconds"),target.stat().st_size)); c.commit(); c.close()
            message=f"Created ZIP: <a href='/archive/{target.name}' target='_blank'>{target.name}</a>"
        except Exception as exc: error=True; message=f"Archive failed: {exc}"
    c=db(); rows=c.execute("SELECT * FROM archives ORDER BY id DESC").fetchall(); c.close()
    return render_template("archives.html",rows=rows,archive_root=ARCHIVE_ROOT,message=message,error=error)

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

if __name__=="__main__":
    ensure_env_admin()
    db().close()
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=False)
