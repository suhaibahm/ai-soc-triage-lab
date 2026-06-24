# SOC-in-a-box

A compact AI-assisted SOC lab for a cybersecurity portfolio. It ingests sample security events, runs simple detection rules, maps alerts to MITRE ATT&CK, and uses Groq to generate practical analyst triage notes.

## What it demonstrates

- Python API development with FastAPI
- Detection engineering with JSON rules
- Security event parsing and alert generation
- MITRE ATT&CK mapping
- Groq LLM integration for alert triage
- Dockerized deployment
- A browser-based analyst dashboard

## Run locally

Install Python 3.12 or newer first.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:GROQ_API_KEY="your_key_here"
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

If `GROQ_API_KEY` is not set, the app still works and returns a local fallback triage summary.

## Validate the sample lab data

This check uses only the Python standard library:

```powershell
python validate_lab.py
```

## Run with Docker

```powershell
copy .env.example .env
# Edit .env and add your Groq key
docker compose up --build
```

Open `http://127.0.0.1:8000`.

## API endpoints

- `GET /api/health`
- `GET /api/events`
- `GET /api/rules`
- `GET /api/alerts`
- `POST /api/triage`

Example triage request:

```json
{
  "alert_id": "alert-0001"
}
```

## CV line

Built a Dockerized AI-assisted SOC lab using Python, FastAPI, JSON detection rules, MITRE ATT&CK mapping, and Groq LLM integration to ingest security events, generate alerts, and produce analyst triage summaries.

## Next improvements

- Add SQLite persistence for analyst notes and alert status.
- Add file upload for custom logs.
- Import Sigma-style detections.
- Add Suricata or Wazuh as an optional event source.
- Add authentication and role-based analyst views.
