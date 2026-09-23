from flask import Flask, jsonify, request, render_template, redirect, url_for, send_from_directory, abort
import os
import sqlite3
import zipfile
from pathlib import Path
from datetime import datetime

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")
ARCHIVE_ROOT = Path(os.environ.get("MCONTROLLER_ARCHIVE_ROOT", "archives")).resolve()
app = Flask(__name__)

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS computers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
      protocol TEXT NOT NULL DEFAULT 'rdp', port INTEGER NOT NULL DEFAULT 3389);
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, display_name TEXT);
    CREATE TABLE IF NOT EXISTS mappings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(computer_id,user_id));
    CREATE TABLE IF NOT EXISTS archives(
      id INTEGER PRIMARY KEY AUTOINCREMENT, source_path TEXT NOT NULL,
      zip_name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0);
    """)
    return c

def safe_zip_name(name):
    return name.replace("/", "_").replace("\\", "_").replace(":", "_").replace("..", "_")

def create_zip_from_path(source):
    source = Path(source).expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(f"Path does not exist: {source}")
    ARCHIVE_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = ARCHIVE_ROOT / f"{safe_zip_name(source.name or 'root')}_{stamp}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        if source.is_file():
            zf.write(source, source.name)
        else:
            for p in source.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(source.parent))
    return source, target

@app.route("/")
def index():
    c=db()
    counts={k:c.execute(f"SELECT COUNT(*) n FROM {k}").fetchone()["n"] for k in ("computers","users","mappings","archives")}
    c.close()
    return render_template("dashboard.html", counts=counts)

@app.route("/computers", methods=["GET","POST"])
def computers():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO computers(name,address,protocol,port) VALUES(?,?,?,?)",
                      (request.form["name"],request.form["address"],request.form.get("protocol","rdp"),
                       int(request.form.get("port",3389))))
            c.commit()
        except (sqlite3.IntegrityError, ValueError):
            pass
        return redirect(url_for("computers"))
    rows=c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    c.close()
    return render_template("computers.html", rows=rows)

@app.route("/users", methods=["GET","POST"])
def users():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO users(username,display_name) VALUES(?,?)",
                      (request.form["username"],request.form.get("display_name","")))
            c.commit()
        except sqlite3.IntegrityError:
            pass
        return redirect(url_for("users"))
    rows=c.execute("SELECT * FROM users ORDER BY username").fetchall()
    c.close()
    return render_template("users.html", rows=rows)

@app.route("/mappings", methods=["GET","POST"])
def mappings():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO mappings(computer_id,user_id) VALUES(?,?)",
                      (request.form["computer_id"],request.form["user_id"]))
            c.commit()
        except sqlite3.IntegrityError:
            pass
        return redirect(url_for("mappings"))
    computers=c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    users=c.execute("SELECT * FROM users ORDER BY username").fetchall()
    rows=c.execute("""SELECT m.id,c.name,c.address,u.username FROM mappings m
                      JOIN computers c ON c.id=m.computer_id
                      JOIN users u ON u.id=m.user_id ORDER BY c.name,u.username""").fetchall()
    c.close()
    return render_template("mappings.html", computers=computers, users=users, rows=rows)

@app.route("/guacamole/<int:mapping_id>")
def guacamole(mapping_id):
    c=db()
    r=c.execute("""SELECT c.*,u.username FROM mappings m
                   JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                   WHERE m.id=?""",(mapping_id,)).fetchone()
    c.close()
    if not r: return "Mapping not found",404
    base=os.environ.get("GUACAMOLE_URL","http://localhost:8080/guacamole/")
    return render_template_string("""<!doctype html><html><head><meta charset="utf-8"><title>Guacamole</title></head>
    <body style="font-family:system-ui;padding:40px"><h1>Apache Guacamole</h1>
    <p>Computer: <b>{{r['name']}}</b> ({{r['address']}})</p><p>User: <b>{{r['username']}}</b></p>
    <p><a href="{{base}}" target="_blank">Open Guacamole ↗</a></p></body></html>""",r=r,base=base)

@app.route("/archives", methods=["GET","POST"])
def archives():
    message=""; error=False
    if request.method=="POST":
        try:
            source_path,target=create_zip_from_path(request.form.get("source_path","").strip())
            c=db()
            c.execute("INSERT INTO archives(source_path,zip_name,created_at,size) VALUES(?,?,?,?)",
                      (str(source_path),target.name,datetime.now().isoformat(timespec="seconds"),target.stat().st_size))
            c.commit(); c.close()
            message=f"Created ZIP: <a href='/archive/{target.name}' target='_blank'>{target.name}</a>"
        except Exception as exc:
            error=True; message=f"Archive failed: {exc}"
    c=db(); rows=c.execute("SELECT * FROM archives ORDER BY id DESC").fetchall(); c.close()
    return render_template("archives.html",rows=rows,archive_root=ARCHIVE_ROOT,message=message,error=error)

@app.route("/archive/<path:filename>")
def archive_file(filename):
    safe=Path(filename).name
    if safe != filename: abort(404)
    target=ARCHIVE_ROOT/safe
    if not target.is_file(): abort(404)
    return send_from_directory(ARCHIVE_ROOT,safe,as_attachment=False)

@app.route("/api/archives")
def api_archives():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM archives ORDER BY id DESC")]; c.close()
    for r in rows: r["url"]=url_for("archive_file",filename=r["zip_name"],_external=False)
    return jsonify(rows)

@app.route("/api/computers")
def api_computers():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM computers ORDER BY name")]; c.close(); return jsonify(rows)

@app.route("/api/users")
def api_users():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM users ORDER BY username")]; c.close(); return jsonify(rows)

@app.route("/api/mappings")
def api_mappings():
    c=db(); rows=[dict(r) for r in c.execute("""SELECT m.id,c.name computer,c.address,u.username
        FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id""")]; c.close(); return jsonify(rows)

if __name__ == "__main__":
    db().close()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")), debug=False)
