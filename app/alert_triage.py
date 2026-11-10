from app.models import SecurityEvent, EventAnalysis, Severity


SEVERITY_SCORES = {
    Severity.LOW: 10,
    Severity.MEDIUM: 40,
    Severity.HIGH: 70,
    Severity.CRITICAL: 95,
}


def triage_event(event: SecurityEvent) -> EventAnalysis:
    """
    Perform deterministic security alert triage.

    This is a demonstration baseline, not a validated
    production threat-detection system.
    """

    risk_score = SEVERITY_SCORES[event.severity]

    if risk_score >= 70:
        classification = "suspicious"
        recommended_action = "Escalate for analyst investigation."

    elif risk_score >= 40:
        classification = "needs_review"
        recommended_action = "Review authentication activity."

    else:
        classification = "benign"
        recommended_action = "Continue monitoring."

    explanation = (
        f"Event severity is {event.severity.value}. "
        f"Assigned risk score: {risk_score}/100. "
        "Classification is based on predefined severity rules."
    )

    return EventAnalysis(
        event_id=event.event_id,
        classification=classification,
        risk_score=risk_score,
        explanation=explanation,
        recommended_action=recommended_action,
    )