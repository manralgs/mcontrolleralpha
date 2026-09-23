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
