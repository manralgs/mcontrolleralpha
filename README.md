# mController Alpha

Initial web-management service for computers, users, mappings, and Apache Guacamole.

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
- JSON APIs for computers, users, and mappings
- Apache Guacamole launch point

Set `GUACAMOLE_URL` to the URL of the Guacamole web application.

## Security

This first version does **not** store passwords or attempt password guessing. Guacamole should own remote-session credentials and authentication. Put the management service behind authentication and HTTPS before exposing it beyond a trusted network.
