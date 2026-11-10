from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "operational"


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_analyze_event():
    event = {
        "event_id": "AUTH-001",
        "timestamp": "2026-11-09T22:00:00Z",
        "category": "authentication",
        "source": "synthetic-auth-server",
        "description": "Multiple failed login attempts detected",
        "severity": "high",
        "raw_log": {
            "failed_attempts": 8,
            "source_ip": "192.0.2.10",
        },
    }

    response = client.post("/events/analyze", json=event)

    assert response.status_code == 200

    result = response.json()

    assert result["event_id"] == "AUTH-001"
    assert result["classification"] == "suspicious"
    assert result["risk_score"] == 70


def test_invalid_severity():
    event = {
        "event_id": "AUTH-002",
        "timestamp": "2026-11-09T22:00:00Z",
        "category": "authentication",
        "source": "synthetic-auth-server",
        "description": "Invalid severity test",
        "severity": "extreme",
    }

    response = client.post("/events/analyze", json=event)

    assert response.status_code == 422


def test_missing_required_fields():
    response = client.post(
        "/events/analyze",
        json={"event_id": "AUTH-003"},
    )

    assert response.status_code == 422