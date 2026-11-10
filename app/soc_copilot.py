from pydantic import BaseModel, Field

from app.models import SecurityEvent, EventAnalysis


class CopilotResponse(BaseModel):
    event_id: str
    summary: str
    classification: str
    risk_score: int = Field(ge=0, le=100)
    supporting_evidence: list[str]
    limitations: list[str]
    recommended_action: str


def explain_alert(
    event: SecurityEvent,
    analysis: EventAnalysis,
) -> CopilotResponse:
    """
    Generate a deterministic explanation from structured
    event data and the existing triage result.

    This function does not call an LLM.
    """

    evidence = [
        f"Event category: {event.category.value}",
        f"Assigned severity: {event.severity.value}",
        f"Event source: {event.source}",
    ]

    if event.category.value == "authentication":
        failed_attempts = event.raw_log.get("failed_attempts")

        if (
            type(failed_attempts) is int
            and failed_attempts >= 0
        ):
            evidence.append(
                f"Failed authentication attempts: {failed_attempts}"
            )

    limitations = [
        "Severity and source fields are supplied by the event producer.",
        "No independent verification of the raw event has occurred.",
        "Risk scores are demonstration values, not calibrated probabilities.",
    ]

    summary = (
        f"Security event {event.event_id} was classified as "
        f"{analysis.classification} with a risk score of "
        f"{analysis.risk_score}/100."
    )

    return CopilotResponse(
        event_id=event.event_id,
        summary=summary,
        classification=analysis.classification,
        risk_score=analysis.risk_score,
        supporting_evidence=evidence,
        limitations=limitations,
        recommended_action=analysis.recommended_action,
    )