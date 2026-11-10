import pytest

from app.alert_triage import triage_event
from app.models import (
    SecurityEvent,
    Severity,
    EventCategory,
)


@pytest.mark.parametrize(
    "severity, expected_score, expected_classification",
    [
        (Severity.LOW, 10, "benign"),
        (Severity.MEDIUM, 40, "needs_review"),
        (Severity.HIGH, 70, "suspicious"),
        (Severity.CRITICAL, 95, "suspicious"),
    ],
)
def test_triage_by_severity(
    severity,
    expected_score,
    expected_classification,
):
    event = SecurityEvent(
        event_id="TRIAGE-001",
        timestamp="2026-11-09T22:00:00Z",
        category=EventCategory.AUTHENTICATION,
        source="synthetic-auth-server",
        description="Synthetic authentication event",
        severity=severity,
        raw_log={},
    )

    result = triage_event(event)

    assert result.event_id == "TRIAGE-001"
    assert result.risk_score == expected_score
    assert result.classification == expected_classification
    assert result.explanation
    assert result.recommended_action


def test_triage_preserves_event_id():
    event = SecurityEvent(
        event_id="AUTH-999",
        timestamp="2026-11-09T22:00:00Z",
        category=EventCategory.AUTHENTICATION,
        source="synthetic-auth-server",
        description="Multiple failed login attempts",
        severity=Severity.HIGH,
    )

    result = triage_event(event)

    assert result.event_id == event.event_id


def test_high_severity_recommends_escalation():
    event = SecurityEvent(
        event_id="AUTH-ESCALATE",
        timestamp="2026-11-09T22:00:00Z",
        category=EventCategory.AUTHENTICATION,
        source="synthetic-auth-server",
        description="Repeated authentication failures",
        severity=Severity.HIGH,
    )

    result = triage_event(event)

    assert result.classification == "suspicious"
    assert "Escalate" in result.recommended_action