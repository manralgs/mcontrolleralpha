from flask import Flask, jsonify, request, render_template_string, redirect, url_for, send_from_directory, abort
import os
import sqlite3
import zipfile
from pathlib import Path
from datetime import datetime

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")
ARCHIVE_ROOT = Path(os.environ.get("MCONTROLLER_ARCHIVE_ROOT", "archives")).resolve()
app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>mController</title>
<style>
body{font-family:system-ui;margin:0;background:#f5f7fb;color:#172033}
nav{padding:16px 24px;background:#172033;color:white}nav a{margin-right:14px}
main{max-width:1100px;margin:24px auto;padding:0 16px}
.card{background:white;padding:18px;margin:14px 0;border-radius:10px;box-shadow:0 2px 8px #0001}
table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left}
input,select,button{padding:8px;margin:4px}button{cursor:pointer}
a{color:#1769aa;text-decoration:none}.error{color:#a00}.ok{color:#176b3a}
code{background:#eef1f5;padding:2px 5px;border-radius:4px}
</style></head><body>
<nav><b>mController</b> &nbsp;
<a href="/" style="color:white">Dashboard</a>
<a href="/computers" style="color:white">Computers</a>
<a href="/users" style="color:white">Users</a>
<a href="/mappings" style="color:white">Mappings</a>
<a href="/archives" style="color:white">Archives</a>
</nav>
<main>{{body|safe}}</main></body></html>"""

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE IF NOT EXISTS computers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      address TEXT NOT NULL,
      protocol TEXT NOT NULL DEFAULT 'rdp',
      port INTEGER NOT NULL DEFAULT 3389
    );
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT
    );
    CREATE TABLE IF NOT EXISTS mappings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(computer_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS archives(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_path TEXT NOT NULL,
      zip_name TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT 0
    );
    """)
    return c

def page(body):
    return render_template_string(PAGE, body=body)

def safe_zip_name(name):
    return name.replace("/", "_").replace("\\", "_").replace(":", "_").replace("..", "_")

def create_zip_from_path(source):
    source = Path(source).expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(f"Path does not exist: {source}")

    ARCHIVE_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = safe_zip_name(source.name or "root")
    zip_name = f"{base}_{stamp}.zip"
    target = ARCHIVE_ROOT / zip_name

    if source.is_file():
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(source, source.name)
    else:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in source.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(source.parent))

    return source, target

@app.route("/")
def index():
    c = db()
    counts={k:c.execute(f"SELECT COUNT(*) n FROM {k}").fetchone()["n"] for k in ("computers","users","mappings","archives")}
    c.close()
    return page(f"""<h1>Dashboard</h1><div class='card'>
    Computers: {counts['computers']}<br>Users: {counts['users']}<br>
    Mappings: {counts['mappings']}<br>Archives: {counts['archives']}
    </div>""")

@app.route("/computers", methods=["GET","POST"])
def computers():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO computers(name,address,protocol,port) VALUES(?,?,?,?)",
                      (request.form["name"],request.form["address"],request.form.get("protocol","rdp"),
                       int(request.form.get("port",3389))))
            c.commit()
        except sqlite3.IntegrityError:
            pass
        return redirect(url_for("computers"))
    rows=c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    c.close()
    body="""<h1>Computers</h1><div class="card"><form method="post">
    <input name="name" placeholder="Computer name" required>
    <input name="address" placeholder="IP / hostname" required>
    <select name="protocol"><option>rdp</option><option>ssh</option><option>vnc</option></select>
    <input name="port" type="number" value="3389"><button>Add</button></form></div>
    <div class="card"><table><tr><th>Name</th><th>Address</th><th>Protocol</th><th>Port</th></tr>"""
    body += "".join(f"<tr><td>{r['name']}</td><td>{r['address']}</td><td>{r['protocol']}</td><td>{r['port']}</td></tr>" for r in rows)
    return page(body+"</table></div>")

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
    body="""<h1>Users</h1><div class="card"><form method="post">
    <input name="username" placeholder="Username" required>
    <input name="display_name" placeholder="Display name"><button>Add</button></form></div>
    <div class="card"><table><tr><th>Username</th><th>Display name</th></tr>"""
    body += "".join(f"<tr><td>{r['username']}</td><td>{r['display_name'] or ''}</td></tr>" for r in rows)
    return page(body+"</table></div>")

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
    rows=c.execute("""SELECT m.id,c.name,c.address,u.username
                      FROM mappings m JOIN computers c ON c.id=m.computer_id
                      JOIN users u ON u.id=m.user_id ORDER BY c.name,u.username""").fetchall()
    c.close()
    options_c="".join(f"<option value='{r['id']}'>{r['name']} ({r['address']})</option>" for r in computers)
    options_u="".join(f"<option value='{r['id']}'>{r['username']}</option>" for r in users)
    body=f"""<h1>Computer ↔ User Mappings</h1><div class="card"><form method="post">
    <select name="computer_id" required>{options_c}</select>
    <select name="user_id" required>{options_u}</select><button>Map</button></form></div>
    <div class="card"><table><tr><th>Computer</th><th>Address</th><th>User</th><th>Guacamole</th></tr>"""
    body += "".join(f"<tr><td>{r['name']}</td><td>{r['address']}</td><td>{r['username']}</td>"
                    f"<td><a href='/guacamole/{r['id']}'>Open connection</a></td></tr>" for r in rows)
    return page(body+"</table></div>")

@app.route("/guacamole/<int:mapping_id>")
def guacamole(mapping_id):
    c=db()
    r=c.execute("""SELECT c.*,u.username FROM mappings m
                   JOIN computers c ON c.id=m.computer_id
                   JOIN users u ON u.id=m.user_id WHERE m.id=?""",(mapping_id,)).fetchone()
    c.close()
    if not r: return "Mapping not found",404
    base=os.environ.get("GUACAMOLE_URL","http://localhost:8080/guacamole/")
    return page(f"""<h1>Apache Guacamole</h1><div class='card'>
    <p>Computer: <b>{r['name']}</b> ({r['address']})</p>
    <p>User: <b>{r['username']}</b></p>
    <p>Configure the corresponding RDP/SSH/VNC connection in Apache Guacamole, then open:</p>
    <p><a href="{base}" target="_blank">{base}</a></p>
    </div>""")

@app.route("/archives", methods=["GET","POST"])
def archives():
    message = ""
    if request.method == "POST":
        source = request.form.get("source_path", "").strip()
        try:
            source_path, target = create_zip_from_path(source)
            size = target.stat().st_size
            c = db()
            c.execute("INSERT INTO archives(source_path,zip_name,created_at,size) VALUES(?,?,?,?)",
                      (str(source_path), target.name, datetime.now().isoformat(timespec="seconds"), size))
            c.commit()
            c.close()
            message = f"<p class='ok'>Created ZIP: <a href='/archive/{target.name}'>{target.name}</a></p>"
        except Exception as exc:
            message = f"<p class='error'>Archive failed: {exc}</p>"

    c = db()
    rows = c.execute("SELECT * FROM archives ORDER BY id DESC").fetchall()
    c.close()
    body = f"""<h1>Path Archive</h1>
    <div class="card">
      <form method="post">
        <label>Local file or directory path:</label><br>
        <input name="source_path" style="width:75%" placeholder="C:\\ProgramData\\Quest\\KACE\\user" required>
        <button type="submit">Create ZIP</button>
      </form>
      <p>Archives are stored under <code>{ARCHIVE_ROOT}</code>.</p>
      {message}
    </div>
    <div class="card"><h2>Browserable Archives</h2>
    <table><tr><th>Source</th><th>Created</th><th>Size</th><th>Link</th></tr>"""
    body += "".join(
        f"<tr><td><code>{r['source_path']}</code></td><td>{r['created_at']}</td>"
        f"<td>{r['size']:,} bytes</td><td><a href='/archive/{r['zip_name']}'>Browse / download</a></td></tr>"
        for r in rows
    )
    return page(body + "</table></div>")

@app.route("/archive/<path:filename>")
def archive_file(filename):
    safe = Path(filename).name
    if safe != filename:
        abort(404)
    target = ARCHIVE_ROOT / safe
    if not target.is_file():
        abort(404)
    return send_from_directory(ARCHIVE_ROOT, safe, as_attachment=False)

@app.route("/api/archives")
def api_archives():
    c=db()
    rows=[dict(r) for r in c.execute("SELECT * FROM archives ORDER BY id DESC")]
    c.close()
    for r in rows:
        r["url"] = url_for("archive_file", filename=r["zip_name"], _external=False)
    return jsonify(rows)

@app.route("/api/computers")
def api_computers():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM computers ORDER BY name")]; c.close()
    return jsonify(rows)

@app.route("/api/users")
def api_users():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM users ORDER BY username")]; c.close()
    return jsonify(rows)

@app.route("/api/mappings")
def api_mappings():
    c=db(); rows=[dict(r) for r in c.execute("""SELECT m.id,c.name computer,c.address,u.username
        FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id""")]; c.close()
    return jsonify(rows)

if __name__ == "__main__":
    db().close()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")), debug=False)
