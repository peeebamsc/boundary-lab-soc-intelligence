import pytest

from app.log_analyzer import analyze_authentication_log
from app.models import Severity, EventCategory


@pytest.mark.parametrize(
    "failed_attempts, expected_severity",
    [
        (0, Severity.LOW),
        (1, Severity.MEDIUM),
        (4, Severity.MEDIUM),
        (5, Severity.HIGH),
        (9, Severity.HIGH),
        (10, Severity.CRITICAL),
        (25, Severity.CRITICAL),
    ],
)
def test_authentication_severity(failed_attempts, expected_severity):
    log = {
        "event_id": "AUTH-TEST",
        "source": "synthetic-auth-server",
        "failed_attempts": failed_attempts,
    }

    event = analyze_authentication_log(log)

    assert event.severity == expected_severity
    assert event.category == EventCategory.AUTHENTICATION
    assert event.event_id == "AUTH-TEST"
    assert event.raw_log["failed_attempts"] == failed_attempts


def test_default_values():
    event = analyze_authentication_log({})

    assert event.event_id == "AUTH-UNKNOWN"
    assert event.severity == Severity.LOW
    assert event.source == "synthetic-auth-server"