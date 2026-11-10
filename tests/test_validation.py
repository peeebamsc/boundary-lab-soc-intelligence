import pytest

from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.log_analyzer import AuthenticationLog


client = TestClient(app)


@pytest.mark.parametrize(
    "invalid_attempts",
    [
        -1,
        "eight",
        "8",
        8.5,
        True,
        None,
        100001,
    ],
)
def test_invalid_failed_attempts(invalid_attempts):
    with pytest.raises(ValidationError):
        AuthenticationLog(
            failed_attempts=invalid_attempts
        )


def test_valid_failed_attempts():
    log = AuthenticationLog(
        event_id="AUTH-VALID",
        failed_attempts=8,
    )

    assert log.failed_attempts == 8


def test_api_rejects_negative_attempts():
    response = client.post(
        "/logs/authentication",
        json={
            "event_id": "AUTH-INVALID",
            "failed_attempts": -5,
        },
    )

    assert response.status_code == 422


def test_api_rejects_string_attempts():
    response = client.post(
        "/logs/authentication",
        json={
            "event_id": "AUTH-INVALID",
            "failed_attempts": "10",
        },
    )

    assert response.status_code == 422


def test_api_accepts_valid_log():
    response = client.post(
        "/logs/authentication",
        json={
            "event_id": "AUTH-VALID",
            "failed_attempts": 12,
        },
    )

    assert response.status_code == 200
    assert response.json()["event"]["severity"] == "critical"