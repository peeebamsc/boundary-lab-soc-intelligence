from typing import Any

from pydantic import BaseModel, Field

from app.log_analyzer import analyze_authentication_log
from app.alert_triage import triage_event
from app.soc_copilot import CopilotResponse, explain_alert
from app.models import SecurityEvent, EventAnalysis


class PipelineResult(BaseModel):
    event: SecurityEvent
    analysis: EventAnalysis
    explanation: CopilotResponse


def process_authentication_log(
    log: dict[str, Any],
) -> PipelineResult:
    """
    Process a synthetic authentication log through
    normalization, triage, and explanation.
    """

    event = analyze_authentication_log(log)

    analysis = triage_event(event)

    explanation = explain_alert(event, analysis)

    return PipelineResult(
        event=event,
        analysis=analysis,
        explanation=explanation,
    )