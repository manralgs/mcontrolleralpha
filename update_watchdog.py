import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

def _restore(project, backup):
    project = Path(project)
    backup = Path(backup)
    for source in backup.rglob("*"):
        relative = source.relative_to(backup)
        target = project / relative
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

def _restart(project):
    command = os.environ.get("MCONTROLLER_UPDATE_COMMAND", "").strip()
    if command:
        subprocess.Popen(command, shell=True, start_new_session=True)
        return
    script = Path(project) / "app.py"
    subprocess.Popen([sys.executable, str(script)], start_new_session=True)

def _healthy(port):
    try:
        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
            return response.status == 200
    except Exception:
        return False

def main():
    backup = os.environ.get("MCONTROLLER_UPDATE_BACKUP", "").strip()
    project = os.environ.get("MCONTROLLER_UPDATE_PROJECT", "").strip()
    port = int(os.environ.get("MCONTROLLER_UPDATE_PORT", "5000"))
    if not backup or not project:
        return
    deadline = time.time() + 45
    while time.time() < deadline:
        if _healthy(port):
            shutil.rmtree(backup, ignore_errors=True)
            return
        time.sleep(1)
    _restore(project, backup)
    shutil.rmtree(backup, ignore_errors=True)
    _restart(project)

if __name__ == "__main__":
    main()
