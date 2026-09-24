import os
import json
import sqlite3
import ipaddress
import socket
import time
import threading
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, Response, send_file

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


def ensure_import_tables():
    c = conn()
    c.execute("""CREATE TABLE IF NOT EXISTS import_jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        account_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        summary TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'preview'
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_import_jobs_account ON import_jobs(account_id)")
    c.commit()
    c.close()

def _permission_for_kind(kind):
    return {"computers":"manage_computers","users":"manage_users","groups":"manage_groups"}[kind]

def _load_import_payload(uploaded, kind):
    if not uploaded:
        raise ValueError("Select a JSON file.")
    try:
        payload=json.loads(uploaded.read().decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid JSON: {exc}")
    expected={"computers":"mcontroller-computers","users":"mcontroller-users","groups":"mcontroller-groups"}[kind]
    if not isinstance(payload, dict) or payload.get("type") != expected or payload.get("version") != 1:
        raise ValueError("Import file does not match the selected object type.")
    if not isinstance(payload.get("items"), list):
        raise ValueError("Import file items must be an array.")
    return payload

def _preview_import(payload, kind):
    c=conn()
    new=updated=unchanged=invalid=0
    errors=[]
    for i,item in enumerate(payload["items"],1):
        try:
            if kind=="computers":
                name=str(item.get("name","")).strip()
                address=str(item.get("address","")).strip()
                if not name or not address:
                    raise ValueError("name and address are required")
                existing=c.execute("SELECT address,protocol,port,os,status,last_seen FROM computers WHERE name=?",(name,)).fetchone()
                normalized=(address,item.get("protocol","rdp"),int(item.get("port",3389)),item.get("os","Windows"),item.get("status","unknown"),item.get("last_seen"))
                if not existing: new+=1
                elif tuple(existing)==normalized: unchanged+=1
                else: updated+=1
            elif kind=="users":
                username=str(item.get("username","")).strip()
                if not username: raise ValueError("username is required")
                existing=c.execute("SELECT display_name FROM users WHERE username=?",(username,)).fetchone()
                value=item.get("display_name","")
                if not existing: new+=1
                elif (existing["display_name"] or "")==(value or ""): unchanged+=1
                else: updated+=1
            else:
                name=str(item.get("name","")).strip()
                if not name: raise ValueError("group name is required")
                existing=c.execute("SELECT description FROM computer_groups WHERE name=?",(name,)).fetchone()
                if not existing: new+=1
                elif (existing["description"] or "")==(item.get("description","") or ""): unchanged+=1
                else: updated+=1
        except Exception as exc:
            invalid+=1
            if len(errors)<25: errors.append({"row":i,"error":str(exc)})
    c.close()
    return {"new":new,"updated":updated,"unchanged":unchanged,"invalid":invalid,"errors":errors,"total":len(payload["items"])}

@enhancements.route("/import-center")
def import_center():
    account=current_user()
    if not account: return redirect(url_for("login",next=request.path))
    kind=request.args.get("kind","computers")
    if kind not in {"computers","users","groups"}: abort(404)
    if _permission_for_kind(kind) not in {"view","manage_computers","manage_users","manage_groups"}:
        abort(403)
    return render_template("import_center.html",kind=kind)

@enhancements.route("/import-center/preview",methods=["POST"])
def import_preview():
    account=current_user()
    if not account: return redirect(url_for("login",next=request.path))
    kind=request.form.get("kind","")
    if kind not in {"computers","users","groups"}: abort(404)
    perm=_permission_for_kind(kind)
    roles={"admin":{"manage_computers","manage_users","manage_groups"},"operator":{"manage_computers","manage_groups"},"viewer":set()}
    if perm not in roles.get(account["role"],set()): return render_template("forbidden.html",permission=perm),403
    try:
        payload=_load_import_payload(request.files.get("file"),kind)
        summary=_preview_import(payload,kind)
        c=conn()
        c.execute("INSERT INTO import_jobs(created_at,account_id,kind,payload,summary,status) VALUES(?,?,?,?,?,?)",
                  (datetime.now().isoformat(timespec="seconds"),account["id"],kind,json.dumps(payload),json.dumps(summary),"preview"))
        job_id=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit(); c.close()
        write_audit("import_preview",kind,job_id,details=summary)
        return redirect(url_for("enhancements.import_job",job_id=job_id))
    except Exception as exc:
        flash(f"Import preview failed: {exc}")
        return redirect(url_for("enhancements.import_center",kind=kind))

@enhancements.route("/import-center/job/<int:job_id>")
def import_job(job_id):
    account=current_user()
    if not account: return redirect(url_for("login",next=request.path))
    c=conn()
    job=c.execute("SELECT * FROM import_jobs WHERE id=?",(job_id,)).fetchone()
    c.close()
    if not job: abort(404)
    if job["account_id"]!=account["id"] and account["role"]!="admin": return render_template("forbidden.html",permission="own import job"),403
    return render_template("import_preview.html",job=job,summary=json.loads(job["summary"]))

@enhancements.route("/import-center/job/<int:job_id>/commit",methods=["POST"])
def import_commit(job_id):
    account=current_user()
    if not account: return redirect(url_for("login",next=request.path))
    c=conn()
    job=c.execute("SELECT * FROM import_jobs WHERE id=?",(job_id,)).fetchone()
    if not job: c.close(); abort(404)
    if job["account_id"]!=account["id"] and account["role"]!="admin": c.close(); return render_template("forbidden.html",permission="own import job"),403
    perm=_permission_for_kind(job["kind"])
    roles={"admin":{"manage_computers","manage_users","manage_groups"},"operator":{"manage_computers","manage_groups"},"viewer":set()}
    if perm not in roles.get(account["role"],set()): c.close(); return render_template("forbidden.html",permission=perm),403
    if job["status"]!="preview": c.close(); flash("This import job has already been processed."); return redirect(url_for("enhancements.import_center",kind=job["kind"]))
    payload=json.loads(job["payload"])
    try:
        if job["kind"]=="computers":
            for item in payload["items"]:
                name=str(item.get("name","")).strip()
                address=str(item.get("address","")).strip()
                if not name or not address: continue
                c.execute("""INSERT INTO computers(name,address,protocol,port,os,status,last_seen) VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(name) DO UPDATE SET address=excluded.address,protocol=excluded.protocol,port=excluded.port,
                    os=excluded.os,status=excluded.status,last_seen=excluded.last_seen""",
                    (name,address,item.get("protocol","rdp"),int(item.get("port",3389)),item.get("os","Windows"),item.get("status","unknown"),item.get("last_seen")))
        elif job["kind"]=="users":
            for item in payload["items"]:
                username=str(item.get("username","")).strip()
                if username:
                    c.execute("""INSERT INTO users(username,display_name) VALUES(?,?)
                        ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name""",(username,item.get("display_name","")))
        else:
            for item in payload["items"]:
                name=str(item.get("name","")).strip()
                if not name: continue
                c.execute("""INSERT INTO computer_groups(name,description) VALUES(?,?)
                    ON CONFLICT(name) DO UPDATE SET description=excluded.description""",(name,item.get("description","")))
                gid=c.execute("SELECT id FROM computer_groups WHERE name=?",(name,)).fetchone()["id"]
                for member in item.get("members",[]):
                    comp=c.execute("SELECT id FROM computers WHERE name=?",(member.get("computer"),)).fetchone()
                    user=c.execute("SELECT id FROM users WHERE username=?",(member.get("username"),)).fetchone()
                    if not comp or not user: continue
                    c.execute("INSERT OR IGNORE INTO mappings(computer_id,user_id) VALUES(?,?)",(comp["id"],user["id"]))
                    mid=c.execute("SELECT id FROM mappings WHERE computer_id=? AND user_id=?",(comp["id"],user["id"])).fetchone()["id"]
                    c.execute("INSERT OR IGNORE INTO computer_group_mappings(group_id,mapping_id) VALUES(?,?)",(gid,mid))
        c.execute("UPDATE import_jobs SET status='committed' WHERE id=?",(job_id,))
        c.commit(); c.close()
        write_audit("import_commit",job["kind"],job_id,details=json.loads(job["summary"]))
        flash(f"{job['kind'].title()} import committed successfully.")
    except Exception as exc:
        c.rollback(); c.close()
        flash(f"Import failed and was rolled back: {exc}")
    return redirect(url_for("enhancements.import_center",kind=job["kind"]))


def mapping_rows(c):
    return c.execute("""SELECT m.id,m.computer_id,m.user_id,c.name computer,c.address,c.protocol,c.port,c.os,
                               c.status,u.username,u.display_name
                        FROM mappings m JOIN computers c ON c.id=m.computer_id
                        JOIN users u ON u.id=m.user_id
                        ORDER BY c.name,u.username""").fetchall()

@enhancements.route("/mapping-center")
@require("view")
def mapping_center():
    q=request.args.get("q","").strip()
    page=max(int(request.args.get("page",1) or 1),1)
    per_page=min(max(int(request.args.get("per_page",25) or 25),10),100)
    c=conn()
    where=[]; params=[]
    if q:
        where.append("(c.name LIKE ? OR c.address LIKE ? OR u.username LIKE ?)")
        params += [f"%{q}%",f"%{q}%",f"%{q}%"]
    clause=(" WHERE "+" AND ".join(where)) if where else ""
    total=c.execute("SELECT COUNT(*) n FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id"+clause,params).fetchone()["n"]
    rows=c.execute("""SELECT m.id,m.computer_id,m.user_id,c.name computer,c.address,c.protocol,c.port,c.os,c.status,u.username
                      FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                      """+clause+" ORDER BY c.name,u.username LIMIT ? OFFSET ?",params+[per_page,(page-1)*per_page]).fetchall()
    c.close()
    return render_template("mapping_center.html",rows=rows,q=q,page=page,pages=max((total+per_page-1)//per_page,1),total=total)

@enhancements.route("/mapping-center/bulk-delete",methods=["POST"])
@require("manage_computers")
def mapping_bulk_delete():
    ids=[int(x) for x in request.form.getlist("ids") if x.isdigit()]
    if not ids:
        flash("Select at least one mapping."); return redirect(url_for("enhancements.mapping_center"))
    c=conn()
    names=[f"{r['computer']} / {r['username']}" for r in c.execute(
        "SELECT c.name computer,u.username FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id WHERE m.id IN (%s)"%(",".join("?"*len(ids))),ids).fetchall()]
    c.execute("DELETE FROM mappings WHERE id IN (%s)"%(",".join("?"*len(ids))),ids); c.commit(); c.close()
    write_audit("mapping_bulk_delete","mapping",details={"count":len(ids),"mappings":names})
    flash(f"Deleted {len(ids)} mapping(s).")
    return redirect(url_for("enhancements.mapping_center"))

@enhancements.route("/mapping-center/export")
@require("view")
def mapping_export():
    c=conn()
    rows=mapping_rows(c)
    payload={"type":"mcontroller-mappings","version":1,"items":[{"computer":r["computer"],"user":r["username"]} for r in rows]}
    c.close()
    response=Response(json.dumps(payload,indent=2),mimetype="application/json")
    response.headers["Content-Disposition"]="attachment; filename=mcontroller-mappings.json"
    return response

@enhancements.route("/mapping-center/orphans")
@require("view")
def mapping_orphans():
    c=conn()
    orphan_users=c.execute("""SELECT u.username FROM users u LEFT JOIN mappings m ON m.user_id=u.id
                              WHERE m.id IS NULL ORDER BY u.username""").fetchall()
    orphan_computers=c.execute("""SELECT c.name,c.address FROM computers c LEFT JOIN mappings m ON m.computer_id=c.id
                                  WHERE m.id IS NULL ORDER BY c.name""").fetchall()
    c.close()
    return render_template("mapping_orphans.html",users=orphan_users,computers=orphan_computers)

@enhancements.route("/mapping-center/test",methods=["POST"])
@require("manage_computers")
def mapping_test():
    ids=[int(x) for x in request.form.getlist("ids") if x.isdigit()]
    c=conn()
    results=[]
    for r in c.execute("""SELECT m.id,c.name,c.address,c.port,c.protocol,u.username
                          FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                          WHERE m.id IN (%s) ORDER BY c.name,u.username"""%(",".join("?"*len(ids))),ids).fetchall() if ids else []:
        try:
            with socket.create_connection((r["address"],int(r["port"])),timeout=0.8):
                result={"id":r["id"],"computer":r["name"],"username":r["username"],"protocol":r["protocol"],"status":"reachable","detail":f"TCP {r['port']} open"}
                _record_connection(r["id"],"success",result["detail"])
        except OSError as exc:
            result={"id":r["id"],"computer":r["name"],"username":r["username"],"protocol":r["protocol"],"status":"unreachable","detail":str(exc)}
            _record_connection(r["id"],"failure",result["detail"])
        results.append(result)
    c.close()
    return render_template("mapping_test.html",results=results)

@enhancements.route("/mapping-center/test-all",methods=["POST"])
@require("manage_computers")
def mapping_test_all():
    c=conn()
    ids=[r["id"] for r in c.execute("SELECT id FROM mappings ORDER BY id").fetchall()]
    c.close()
    request.form
    # Reuse the same test logic through a redirect-friendly temporary result page.
    c=conn(); results=[]
    for r in c.execute("""SELECT m.id,c.name,c.address,c.port,c.protocol,u.username
                          FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                          ORDER BY c.name,u.username""").fetchall():
        try:
            with socket.create_connection((r["address"],int(r["port"])),timeout=0.8):
                results.append({"id":r["id"],"computer":r["name"],"username":r["username"],"protocol":r["protocol"],"status":"reachable","detail":f"TCP {r['port']} open"})
                _record_connection(r["id"],"success",results[-1]["detail"])
        except OSError as exc:
            results.append({"id":r["id"],"computer":r["name"],"username":r["username"],"protocol":r["protocol"],"status":"unreachable","detail":str(exc)})
            _record_connection(r["id"],"failure",results[-1]["detail"])
    c.close()
    write_audit("mapping_test_all","mapping",details={"count":len(results)})
    return render_template("mapping_test.html",results=results)


def _backup_root():
    root=Path(os.environ.get("MCONTROLLER_BACKUP_ROOT",str(Path("runtime")/"backups"))).expanduser().resolve()
    root.mkdir(parents=True,exist_ok=True)
    return root

def _backup_payload():
    c=conn()
    data={}
    for table in ("computers","users","mappings","computer_groups","computer_group_mappings","server_settings","software_updates"):
        rows=c.execute(f"SELECT * FROM {table}").fetchall()
        data[table]=[dict(row) for row in rows]
    c.close()
    return {"type":"mcontroller-backup","version":1,"created_at":datetime.now().isoformat(timespec="seconds"),"tables":data}

@enhancements.route("/backup")
@require("view")
def backup_center():
    root=_backup_root()
    files=sorted(root.glob("*.json"),key=lambda p:p.stat().st_mtime,reverse=True)
    return render_template("backup_center.html",files=[{"name":p.name,"size":p.stat().st_size,"created_at":datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")} for p in files])

@enhancements.route("/backup/create",methods=["POST"])
@require("manage_updates")
def backup_create():
    payload=_backup_payload()
    name="mcontroller-backup-"+datetime.now().strftime("%Y%m%d_%H%M%S")+".json"
    path=_backup_root()/name
    path.write_text(json.dumps(payload,indent=2,default=str),encoding="utf-8")
    write_audit("backup_create","backup",object_name=name,details={"size":path.stat().st_size})
    flash("Backup created.")
    return redirect(url_for("enhancements.backup_center"))

@enhancements.route("/backup/download/<path:name>")
@require("view")
def backup_download(name):
    root=_backup_root()
    path=(root/name).resolve()
    if path.parent!=root or path.suffix.lower()!=".json" or not path.is_file(): abort(404)
    return send_file(path,as_attachment=True,download_name=path.name)

@enhancements.route("/backup/restore/<path:name>")
@require("manage_updates")
def backup_restore_preview(name):
    root=_backup_root(); path=(root/name).resolve()
    if path.parent!=root or not path.is_file(): abort(404)
    try:
        payload=json.loads(path.read_text(encoding="utf-8"))
        if payload.get("type")!="mcontroller-backup" or payload.get("version")!=1: raise ValueError("Unsupported backup format.")
        tables=payload.get("tables",{})
        required={"computers","users","mappings","computer_groups","computer_group_mappings","server_settings","software_updates"}
        missing=required-set(tables)
        if missing: raise ValueError("Backup is missing: "+", ".join(sorted(missing)))
        summary={k:len(v) for k,v in tables.items()}
    except Exception as exc:
        return render_template("backup_restore.html",name=name,error=str(exc),summary={})
    return render_template("backup_restore.html",name=name,error=None,summary=summary)

@enhancements.route("/backup/restore/<path:name>/commit",methods=["POST"])
@require("manage_updates")
def backup_restore_commit(name):
    root=_backup_root(); path=(root/name).resolve()
    if path.parent!=root or not path.is_file(): abort(404)
    try:
        payload=json.loads(path.read_text(encoding="utf-8"))
        if payload.get("type")!="mcontroller-backup" or payload.get("version")!=1: raise ValueError("Unsupported backup format.")
        tables=payload["tables"]
        pre=_backup_payload()
        pre_name="pre-restore-"+datetime.now().strftime("%Y%m%d_%H%M%S")+".json"
        (_backup_root()/pre_name).write_text(json.dumps(pre,indent=2,default=str),encoding="utf-8")
        c=conn()
        try:
            c.execute("BEGIN")
            for table in ("computer_group_mappings","mappings","computer_groups","server_settings","software_updates","computers","users"):
                c.execute(f"DELETE FROM {table}")
            for row in tables["computers"]:
                c.execute("INSERT INTO computers VALUES (?,?,?,?,?,?,?,?)",tuple(row.values()))
            for row in tables["users"]:
                c.execute("INSERT INTO users VALUES (?,?,?)",tuple(row.values()))
            for row in tables["mappings"]:
                c.execute("INSERT INTO mappings VALUES (?,?,?)",tuple(row.values()))
            for row in tables["computer_groups"]:
                c.execute("INSERT INTO computer_groups VALUES (?,?,?)",tuple(row.values()))
            for row in tables["computer_group_mappings"]:
                c.execute("INSERT INTO computer_group_mappings VALUES (?,?)",tuple(row.values()))
            for row in tables["server_settings"]:
                c.execute("INSERT INTO server_settings VALUES (?,?)",tuple(row.values()))
            for row in tables["software_updates"]:
                c.execute("""INSERT INTO software_updates
                    (id,name,version,platform,package_url,install_command,release_notes,created_at,sha256)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    tuple(row.get(k) for k in ("id","name","version","platform","package_url","install_command","release_notes","created_at","sha256")))
            c.commit()
        except Exception:
            c.rollback(); raise
        finally: c.close()
        write_audit("backup_restore","backup",object_name=name,details={"pre_restore_backup":pre_name,"tables":{k:len(v) for k,v in tables.items()}})
        flash("Backup restored successfully. A pre-restore backup was created.")
    except Exception as exc:
        flash("Restore failed: "+str(exc))
    return redirect(url_for("enhancements.backup_center"))


def _health_init():
    c=conn()
    c.execute("""CREATE TABLE IF NOT EXISTS computer_health(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms REAL,
        detail TEXT
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_health_computer_checked ON computer_health(computer_id,checked_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_health_checked ON computer_health(checked_at)")
    c.commit(); c.close()

def _check_computer_health(row, timeout=0.8):
    started=time.monotonic()
    try:
        with socket.create_connection((row["address"],int(row["port"])),timeout=timeout):
            latency=round((time.monotonic()-started)*1000,1)
            return "online",latency,f"TCP {row['port']} reachable"
    except OSError as exc:
        return "offline",None,str(exc)

@enhancements.route("/health")
@require("view")
def health_center():
    _health_init()
    c=conn()
    rows=c.execute("""SELECT c.*,h.checked_at,h.status health_status,h.latency_ms,h.detail
                      FROM computers c LEFT JOIN computer_health h ON h.id=(
                        SELECT h2.id FROM computer_health h2 WHERE h2.computer_id=c.id ORDER BY h2.id DESC LIMIT 1)
                      ORDER BY c.name""").fetchall()
    c.close()
    return render_template("health.html",rows=rows)

@enhancements.route("/health/check",methods=["POST"])
@require("scan")
def health_check():
    _health_init()
    c=conn()
    rows=c.execute("SELECT * FROM computers ORDER BY name").fetchall()
    results=[]
    for row in rows:
        status,latency,detail=_check_computer_health(row)
        now=datetime.now().isoformat(timespec="seconds")
        c.execute("INSERT INTO computer_health(computer_id,checked_at,status,latency_ms,detail) VALUES(?,?,?,?,?)",
                  (row["id"],now,status,latency,detail))
        c.execute("UPDATE computers SET status=?,last_seen=? WHERE id=?",
                  (status,now if status=="online" else row["last_seen"],row["id"]))
        results.append({"name":row["name"],"status":status,"latency_ms":latency})
    c.commit(); c.close()
    write_audit("health_check","computer",details={"count":len(results),"online":sum(x["status"]=="online" for x in results)})
    flash(f"Health check completed: {sum(x['status']=='online' for x in results)} online, {sum(x['status']=='offline' for x in results)} offline.")
    return redirect(url_for("enhancements.health_center"))

@enhancements.route("/health/<int:computer_id>")
@require("view")
def health_history(computer_id):
    _health_init()
    c=conn()
    computer=c.execute("SELECT * FROM computers WHERE id=?",(computer_id,)).fetchone()
    if not computer: c.close(); abort(404)
    history=c.execute("""SELECT checked_at,status,latency_ms,detail FROM computer_health
                         WHERE computer_id=? ORDER BY id DESC LIMIT 100""",(computer_id,)).fetchall()
    c.close()
    return render_template("health_history.html",computer=computer,history=history)


def _discovery_init():
    c=conn()
    c.execute("""CREATE TABLE IF NOT EXISTS discovery_jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        target TEXT NOT NULL,
        ports TEXT NOT NULL DEFAULT '22,3389,5900',
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run TEXT,
        created_at TEXT NOT NULL
    )""")
    existing={row["name"] for row in c.execute("PRAGMA table_info(discovery_jobs)").fetchall()}
    if "interval_minutes" not in existing:
        c.execute("ALTER TABLE discovery_jobs ADD COLUMN interval_minutes INTEGER NOT NULL DEFAULT 60")
    c.execute("""CREATE TABLE IF NOT EXISTS discovery_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
        address TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        UNIQUE(job_id,address,port)
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_discovery_results_job ON discovery_results(job_id,last_seen)")
    c.commit(); c.close()

def _run_discovery(job):
    target=ipaddress.ip_network(job["target"],strict=False)
    if target.version!=4 or not target.is_private or target.prefixlen<16 or len(list(target.hosts()))>1024:
        raise ValueError("Discovery requires a private IPv4 /16-/32 range with at most 1024 hosts.")
    ports=[int(x.strip()) for x in job["ports"].split(",") if x.strip().isdigit() and 1<=int(x.strip())<=65535]
    now=datetime.now().isoformat(timespec="seconds")
    c=conn(); found=[]
    for ip in target.hosts():
        opened=probe_host(str(ip),ports)
        for port in opened:
            protocol=protocol_for_port(port)
            c.execute("""INSERT INTO discovery_results(job_id,address,port,protocol,first_seen,last_seen,status)
                         VALUES(?,?,?,?,?,?, 'pending')
                         ON CONFLICT(job_id,address,port) DO UPDATE SET last_seen=excluded.last_seen,status='pending',protocol=excluded.protocol""",
                      (job["id"],str(ip),port,protocol,now,now))
            found.append((str(ip),port,protocol))
    c.execute("UPDATE discovery_jobs SET last_run=? WHERE id=?",(now,job["id"]))
    c.commit(); c.close()
    return found

@enhancements.route("/discovery",methods=["GET","POST"])
@require("scan")
def discovery():
    _discovery_init(); c=conn()
    if request.method=="POST":
        name=request.form.get("name","").strip(); target=request.form.get("target","").strip()
        ports=request.form.get("ports","22,3389,5900").strip()
        try:
            interval_minutes=int(request.form.get("interval_minutes","60").strip() or "60")
        except ValueError:
            interval_minutes=60
        interval_minutes=min(max(interval_minutes,5),1440)
        if name and target:
            try:
                network=ipaddress.ip_network(target,strict=False)
                if network.version!=4 or not network.is_private or network.prefixlen<16 or len(list(network.hosts()))>1024:
                    raise ValueError("Discovery requires a private IPv4 /16-/32 range with at most 1024 hosts.")
                if not any(x.strip().isdigit() and 1<=int(x.strip())<=65535 for x in ports.split(",")):
                    raise ValueError("Enter at least one valid TCP port.")
                c.execute("INSERT INTO discovery_jobs(name,target,ports,interval_minutes,enabled,created_at) VALUES(?,?,?,?,?,?)",
                          (name,target,ports,interval_minutes,1,datetime.now().isoformat(timespec="seconds"))); c.commit()
                flash("Discovery job created.")
            except (ValueError,sqlite3.IntegrityError) as exc: flash("Unable to create job: "+str(exc))
        return redirect(url_for("enhancements.discovery"))
    jobs=c.execute("SELECT * FROM discovery_jobs ORDER BY name").fetchall()
    results=c.execute("""SELECT r.*,j.name job_name FROM discovery_results r JOIN discovery_jobs j ON j.id=r.job_id
                         ORDER BY r.last_seen DESC LIMIT 250""").fetchall()
    c.close()
    return render_template("discovery.html",jobs=jobs,results=results)

@enhancements.route("/discovery/<int:job_id>/run",methods=["POST"])
@require("scan")
def discovery_run(job_id):
    _discovery_init(); c=conn(); job=c.execute("SELECT * FROM discovery_jobs WHERE id=?",(job_id,)).fetchone(); c.close()
    if not job: abort(404)
    try:
        found=_run_discovery(job)
        write_audit("discovery_run","discovery_job",object_id=str(job_id),object_name=job["name"],details={"found":len(found)})
        flash(f"Discovery completed: {len(found)} endpoint(s) detected.")
    except Exception as exc: flash("Discovery failed: "+str(exc))
    return redirect(url_for("enhancements.discovery"))

@enhancements.route("/discovery/result/<int:result_id>/add",methods=["POST"])
@require("manage_computers")
def discovery_add(result_id):
    _discovery_init(); c=conn()
    r=c.execute("SELECT * FROM discovery_results WHERE id=?",(result_id,)).fetchone()
    if not r: c.close(); abort(404)
    name=request.form.get("name",r["address"]).strip() or r["address"]
    try:
        c.execute("INSERT INTO computers(name,address,protocol,port,os,status) VALUES(?,?,?,?,?,?)",
                  (name,r["address"],r["protocol"],r["port"],"Unknown","discovered"))
        c.commit(); c.execute("UPDATE discovery_results SET status='added' WHERE id=?",(result_id,)); c.commit()
        flash(f"Added {name}.")
    except sqlite3.IntegrityError: flash("A computer with that name already exists.")
    c.close()
    return redirect(url_for("enhancements.discovery"))

@enhancements.route("/discovery/result/<int:result_id>/dismiss",methods=["POST"])
@require("scan")
def discovery_dismiss(result_id):
    _discovery_init(); c=conn(); c.execute("UPDATE discovery_results SET status='dismissed' WHERE id=?",(result_id,)); c.commit(); c.close()
    return redirect(url_for("enhancements.discovery"))


def _discovery_scheduler_loop():
    while True:
        try:
            _discovery_init()
            c=conn()
            jobs=c.execute("SELECT * FROM discovery_jobs WHERE enabled=1 ORDER BY id").fetchall()
            c.close()
            now=time.time()
            for job in jobs:
                last=0
                if job["last_run"]:
                    try: last=datetime.fromisoformat(job["last_run"]).timestamp()
                    except ValueError: last=0
                interval=int(job["interval_minutes"]) if "interval_minutes" in job.keys() and job["interval_minutes"] else 60
                if now-last >= max(int(interval),5)*60:
                    try: _run_discovery(job)
                    except Exception: pass
            time.sleep(60)
        except Exception:
            time.sleep(60)

def _start_discovery_scheduler(app):
    if getattr(app,"_discovery_scheduler_started",False): return
    app._discovery_scheduler_started=True
    threading.Thread(target=_discovery_scheduler_loop,name="discovery-scheduler",daemon=True).start()


def _connection_history_init():
    c=conn()
    c.execute("""CREATE TABLE IF NOT EXISTS connection_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mapping_id INTEGER,
        computer_id INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
        user_id INTEGER,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        result TEXT NOT NULL,
        protocol TEXT NOT NULL,
        address TEXT NOT NULL,
        port INTEGER NOT NULL,
        detail TEXT
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connection_history_computer ON connection_history(computer_id,started_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_connection_history_result ON connection_history(result)")
    c.commit(); c.close()

@enhancements.route("/connections")
@require("view")
def connection_history():
    _connection_history_init()
    q=request.args.get("q","").strip()
    c=conn()
    params=[]; where=""
    if q:
        where="WHERE c.name LIKE ? OR c.address LIKE ? OR COALESCE(u.username,'') LIKE ?"
        params=[f"%{q}%",f"%{q}%",f"%{q}%"]
    rows=c.execute("""SELECT h.*,c.name computer,COALESCE(u.username,'') username
                      FROM connection_history h JOIN computers c ON c.id=h.computer_id
                      LEFT JOIN users u ON u.id=h.user_id
                      """+where+" ORDER BY h.id DESC LIMIT 250",params).fetchall()
    c.close()
    return render_template("connections.html",rows=rows,q=q)

@enhancements.route("/connections/<int:history_id>")
@require("view")
def connection_detail(history_id):
    _connection_history_init()
    c=conn()
    row=c.execute("""SELECT h.*,c.name computer,COALESCE(u.username,'') username
                     FROM connection_history h JOIN computers c ON c.id=h.computer_id
                     LEFT JOIN users u ON u.id=h.user_id WHERE h.id=?""",(history_id,)).fetchone()
    c.close()
    if not row: abort(404)
    return render_template("connection_detail.html",row=row)

def _record_connection(mapping_id, result, detail):
    _connection_history_init()
    c=conn()
    mapping=c.execute("""SELECT m.id,c.id computer_id,u.id user_id,c.name,c.address,c.protocol,c.port,u.username
                         FROM mappings m JOIN computers c ON c.id=m.computer_id JOIN users u ON u.id=m.user_id
                         WHERE m.id=?""",(mapping_id,)).fetchone()
    if not mapping: c.close(); return
    now=datetime.now().isoformat(timespec="seconds")
    c.execute("""INSERT INTO connection_history(mapping_id,computer_id,user_id,started_at,ended_at,result,protocol,address,port,detail)
                 VALUES(?,?,?,?,?,?,?,?,?,?)""",
              (mapping["id"],mapping["computer_id"],mapping["user_id"],now,now,result,mapping["protocol"],mapping["address"],mapping["port"],detail))
    c.commit(); c.close()

def security_audit_cleanup():
    c=conn()
    c.execute("DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)")
    c.commit(); c.close()

@enhancements.route("/audit/retention",methods=["POST"])
@require("manage_updates")
def audit_retention():
    security_audit_cleanup()
    write_audit("audit_retention","audit_log",details={"retained":"5000 newest records"})
    flash("Audit log retention cleanup completed.")
    return redirect(url_for("enhancements.audit"))

def register_enhancements(app):
    ensure_tables()
    ensure_import_tables()
    app.register_blueprint(enhancements)
    _start_discovery_scheduler(app)

    @app.after_request
    def audit_mutations(response):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path not in {"/login", "/setup"}:
            try:
                write_audit("request", details={"status_code":response.status_code}, result="success" if response.status_code < 400 else "failed")
            except Exception:
                pass
        return response
