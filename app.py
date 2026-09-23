from flask import Flask, jsonify, request, render_template_string, redirect, url_for
import os
import sqlite3

DB = os.environ.get("MCONTROLLER_DB", "mcontroller.db")
app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>mController</title>
<style>
body{font-family:system-ui;margin:0;background:#f5f7fb;color:#172033}
nav{padding:16px 24px;background:#172033;color:white}main{max-width:1100px;margin:24px auto;padding:0 16px}
.card{background:white;padding:18px;margin:14px 0;border-radius:10px;box-shadow:0 2px 8px #0001}
table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left}
input,select,button{padding:8px;margin:4px}button{cursor:pointer}
a{color:#1769aa;text-decoration:none}
</style></head><body>
<nav><b>mController</b> &nbsp; <a href="/" style="color:white">Dashboard</a> &nbsp;
<a href="/computers" style="color:white">Computers</a> &nbsp;
<a href="/users" style="color:white">Users</a> &nbsp;
<a href="/mappings" style="color:white">Mappings</a></nav>
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
    """)
    return c

def page(body):
    return render_template_string(PAGE, body=body)

@app.route("/")
def index():
    c=db()
    counts={k:c.execute(f"SELECT COUNT(*) n FROM {k}").fetchone()["n"] for k in ("computers","users","mappings")}
    c.close()
    return page(f"<h1>Dashboard</h1><div class='card'>Computers: {counts['computers']}<br>Users: {counts['users']}<br>Mappings: {counts['mappings']}</div>")

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
    # The Guacamole URL is intentionally configurable; credentials are never stored here.
    base=os.environ.get("GUACAMOLE_URL","http://localhost:8080/guacamole/")
    return page(f"""<h1>Apache Guacamole</h1><div class='card'>
    <p>Computer: <b>{r['name']}</b> ({r['address']})</p>
    <p>User: <b>{r['username']}</b></p>
    <p>Configure the corresponding RDP/SSH/VNC connection in Apache Guacamole, then open:</p>
    <p><a href="{base}" target="_blank">{base}</a></p>
    </div>""")

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
