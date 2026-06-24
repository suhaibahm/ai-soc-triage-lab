import json
import os
import asyncio
from enum import Enum
from functools import lru_cache
from pathlib import Path
from textwrap import dedent
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    source: str
    host: str
    username: str | None = None
    event_type: str
    message: str
    src_ip: str | None = None
    dest_ip: str | None = None
    process: str | None = None
    command_line: str | None = None
    raw: dict = Field(default_factory=dict)


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    event_type: str | None = None
    keywords: list[str] = Field(default_factory=list)
    mitre_technique: str
    mitre_tactic: str
    analyst_guidance: str


class Alert(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    event: SecurityEvent
    mitre_technique: str
    mitre_tactic: str
    analyst_guidance: str


class TriageRequest(BaseModel):
    alert_id: str


class TriageResponse(BaseModel):
    alert_id: str
    provider: str
    model: str
    summary: str


app = FastAPI(
    title="SOC-in-a-box",
    description="A small AI-assisted SOC lab for alert triage and detection engineering practice.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_json(filename: str) -> list[dict]:
    with (BASE_DIR / filename).open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache
def load_events() -> list[SecurityEvent]:
    return [SecurityEvent(**item) for item in load_json("sample_events.json")]


@lru_cache
def load_rules() -> list[DetectionRule]:
    return [DetectionRule(**item) for item in load_json("detection_rules.json")]


def event_matches_rule(event: SecurityEvent, rule: DetectionRule) -> bool:
    if rule.event_type and event.event_type != rule.event_type:
        return False

    haystack = " ".join(
        value or ""
        for value in [
            event.message,
            event.process,
            event.command_line,
            event.username,
            event.src_ip,
            event.dest_ip,
        ]
    ).lower()

    return all(keyword.lower() in haystack for keyword in rule.keywords)


@lru_cache
def load_alerts() -> list[Alert]:
    alerts: list[Alert] = []
    for event in load_events():
        for rule in load_rules():
            if event_matches_rule(event, rule):
                alerts.append(
                    Alert(
                        id=f"alert-{len(alerts) + 1:04d}",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        event=event,
                        mitre_technique=rule.mitre_technique,
                        mitre_tactic=rule.mitre_tactic,
                        analyst_guidance=rule.analyst_guidance,
                    )
                )
    return alerts


def get_alert(alert_id: str) -> Alert | None:
    return next((alert for alert in load_alerts() if alert.id == alert_id), None)


def fallback_summary(alert: Alert) -> str:
    return dedent(
        f"""
        Groq is not configured yet, so this is a local triage summary.

        Alert: {alert.rule_name}
        Severity: {alert.severity.value}
        Host: {alert.event.host}
        User: {alert.event.username or "unknown"}
        MITRE: {alert.mitre_tactic} / {alert.mitre_technique}

        Why it matters:
        {alert.event.message}

        Recommended first checks:
        1. Confirm whether the user and host activity is expected.
        2. Review surrounding authentication, process, and network logs.
        3. Check whether the command, source IP, or process appears elsewhere.
        4. Escalate if the activity is unexplained or repeats across hosts.
        """
    ).strip()


def build_triage_prompt(alert: Alert) -> str:
    return dedent(
        f"""
        You are a SOC analyst assistant. Triage this alert for a junior analyst.
        Be concise, practical, and avoid making claims not supported by the event.

        Alert:
        - Name: {alert.rule_name}
        - Severity: {alert.severity.value}
        - MITRE tactic: {alert.mitre_tactic}
        - MITRE technique: {alert.mitre_technique}
        - Guidance: {alert.analyst_guidance}

        Event:
        - Time: {alert.event.timestamp}
        - Source: {alert.event.source}
        - Host: {alert.event.host}
        - User: {alert.event.username}
        - Type: {alert.event.event_type}
        - Message: {alert.event.message}
        - Source IP: {alert.event.src_ip}
        - Destination IP: {alert.event.dest_ip}
        - Process: {alert.event.process}
        - Command line: {alert.event.command_line}

        Return:
        1. One-sentence summary
        2. Why this could be suspicious
        3. Immediate investigation steps
        4. Likely false-positive reasons
        5. Suggested incident note
        """
    ).strip()


async def triage_alert(alert: Alert) -> tuple[str, str, str]:
    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL)

    if not api_key:
        return "local-fallback", model, fallback_summary(alert)

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a careful cybersecurity SOC analyst assistant.",
            },
            {"role": "user", "content": build_triage_prompt(alert)},
        ],
        "temperature": 0.2,
        "max_completion_tokens": 700,
    }

    data = await asyncio.to_thread(call_groq, api_key, payload)

    return "groq", model, data["choices"][0]["message"]["content"]


def call_groq(api_key: str, payload: dict) -> dict:
    request = Request(
        GROQ_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "soc-in-a-box-lab/0.1",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        if "error code: 1010" in body.lower():
            message = (
                "Groq/Cloudflare rejected the request with error 1010. "
                "Try restarting the app after this update, confirm your API key is active, "
                "and try again from your normal home network or a different network."
            )
        else:
            message = f"Groq API error: {body}"
        raise HTTPException(status_code=502, detail=message) from error
    except URLError as error:
        raise HTTPException(status_code=502, detail=f"Could not reach Groq API: {error.reason}") from error


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/events")
def events() -> list[SecurityEvent]:
    return load_events()


@app.get("/api/rules")
def rules() -> list[DetectionRule]:
    return load_rules()


@app.get("/api/alerts")
def alerts() -> list[Alert]:
    return load_alerts()


@app.post("/api/triage", response_model=TriageResponse)
async def triage(request: TriageRequest) -> TriageResponse:
    alert = get_alert(request.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    provider, model, summary = await triage_alert(alert)
    return TriageResponse(
        alert_id=alert.id,
        provider=provider,
        model=model,
        summary=summary,
    )
