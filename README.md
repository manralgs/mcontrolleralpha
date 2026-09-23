# mController Alpha

Initial web-management service for computers, users, mappings, Apache Guacamole, and local path archiving.

## Run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Modules

- Web server
- Computer list
- User list
- Computer-to-user mapping
- JSON APIs for computers, users, mappings, and archives
- Apache Guacamole launch point
- **Path Archive**: enter a local file or directory path, package it as a ZIP, store it under the archive root, and expose a browserable link.

## Path Archive

Open **Archives** in the web UI or use `POST /archives` with `source_path`.

Default ZIP storage is `./archives`. Override it with:

```text
MCONTROLLER_ARCHIVE_ROOT=D:\\mcontroller\\archives
```

Each archive receives a timestamped ZIP name. The archive list shows the original source path, creation time, size, and a browser/download link.

The API endpoint `/api/archives` returns the archive metadata and relative browser URL.

## Apache Guacamole

Set `GUACAMOLE_URL` to the URL of the Guacamole web application.

## Security

The archive feature operates with the permissions of the account running the web server. Do not expose this endpoint to untrusted users: an unrestricted server-side path input can read any file/directory accessible to that account. In production, add authentication and restrict allowed source roots before exposing it outside a trusted administration network.

Remote credentials are not stored or guessed by this application; Guacamole should own remote-session authentication.


## Current administration features

- First-run administrator setup plus login/logout sessions.
- RBAC roles: `admin`, `operator`, and `viewer`.
- Management account creation, role changes, and account enable/disable.
- Computer inventory for Windows, Linux, and macOS using RDP, SSH, or VNC.
- Private-network computer discovery with SSH/RDP/VNC port probing and one-click add.
- Computer ↔ remote-user mappings and reusable computer groups.
- Apache Guacamole launch point; SSH endpoints also expose system SSH and PuTTY command details.
- Software Updates page for release/version/platform/package URL/install-command metadata. This build does not execute update commands automatically.
- Existing SQLite databases receive a lightweight migration for the new computer fields.

### First login

If no management account exists, open `/setup` and create the first administrator. For unattended deployment, set `MCONTROLLER_ADMIN_USERNAME` and `MCONTROLLER_ADMIN_PASSWORD` before starting the service. Set `MCONTROLLER_SECRET_KEY` to a persistent random value in production.

### Remote access

Use SSH for Linux and macOS. Use RDP for Windows. Apache Guacamole remains the browser-based access layer; PuTTY is supported as a native SSH client through the generated command shown on an SSH mapping.

### Discovery

`Scan & Add` is intentionally limited to private IPv4 networks and at most 1024 hosts per request. It probes only the ports entered by the operator (by default 22, 3389, and 5900).
