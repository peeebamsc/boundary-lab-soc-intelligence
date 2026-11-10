import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.pipeline import process_authentication_log


client = TestClient(app)


@pytest.mark.parametrize(
    "attempts, expected_severity, expected_score, expected_class",
    [
        (0, "low", 10, "benign"),
        (3, "medium", 40, "needs_review"),
        (8, "high", 70, "suspicious"),
        (15, "critical", 95, "suspicious"),
    ],
)
def test_pipeline_classification(
    attempts,
    expected_severity,
    expected_score,
    expected_class,
):
    result = process_authentication_log({
        "event_id": "AUTH-PIPELINE",
        "failed_attempts": attempts,
        "source": "synthetic-auth-server",
    })

    assert result.event.severity.value == expected_severity
    assert result.analysis.risk_score == expected_score
    assert result.analysis.classification == expected_class
    assert result.explanation.classification == expected_class


def test_pipeline_api():
    response = client.post(
        "/logs/authentication",
        json={
            "event_id": "AUTH-3001",
            "failed_attempts": 12,
            "source": "synthetic-auth-server",
        },
    )

    assert response.status_code == 200

    result = response.json()

    assert result["event"]["severity"] == "critical"
    assert result["analysis"]["risk_score"] == 95
    assert result["analysis"]["classification"] == "suspicious"


def test_pipeline_ignores_supplied_severity():
    result = process_authentication_log({
        "event_id": "AUTH-3002",
        "failed_attempts": 12,
        "severity": "low",
    })

    assert result.event.severity.value == "critical"
    assert result.analysis.risk_score == 95


def test_pipeline_explanation_matches_triage():
    result = process_authentication_log({
        "event_id": "AUTH-3003",
        "failed_attempts": 8,
    })

    assert (
        result.explanation.classification
        == result.analysis.classification
    )

    assert (
        result.explanation.risk_score
        == result.analysis.risk_score
    )