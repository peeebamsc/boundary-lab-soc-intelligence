from fastapi import FastAPI
from typing import Any

from app.pipeline import PipelineResult, process_authentication_log
from app.models import SecurityEvent, EventAnalysis
from app.alert_triage import triage_event
from app.soc_copilot import CopilotResponse, explain_alert
from app.log_analyzer import AuthenticationLog
from app.database import save_event, get_events
from app.ai_analyst import generate_ai_analysis


app = FastAPI(
    title="BOUNDARY//LAB SOC Intelligence",
    description="AI Security Evaluation and SOC Intelligence Platform",
    version="0.2.0",
)


@app.get("/")
def root():
    return {
        "project": "BOUNDARY//LAB SOC Intelligence",
        "status": "operational",
        "version": "0.2.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "soc-intelligence-api",
    }


@app.post("/events/analyze", response_model=EventAnalysis)
def analyze_event(event: SecurityEvent):
    return triage_event(event)

@app.post("/events/explain", response_model=CopilotResponse)
def explain_event(event: SecurityEvent):
    analysis = triage_event(event)
    return explain_alert(event, analysis)

@app.post("/logs/authentication", response_model=PipelineResult)
def process_authentication(log: AuthenticationLog):
    result = process_authentication_log(log.model_dump())

    save_event(result)

    return result

@app.get("/events/history")
def event_history():
    return get_events()

@app.post("/ai/analyze")
def ai_analyze_event(event: SecurityEvent):
    from app.alert_triage import triage_event

    analysis = triage_event(event)

    return generate_ai_analysis(event, analysis)