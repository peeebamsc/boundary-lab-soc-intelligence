from app.database import (
    initialize_database,
    save_event,
    get_events,
)
from app.pipeline import process_authentication_log


def test_database_initialization(tmp_path):
    database = tmp_path / "test_soc.db"

    initialize_database(database)

    assert database.exists()


def test_save_security_event(tmp_path):
    database = tmp_path / "test_soc.db"

    result = process_authentication_log({
        "event_id": "AUTH-DB-001",
        "failed_attempts": 8,
    })

    save_event(result, database)

    events = get_events(database)

    assert len(events) == 1
    assert events[0]["event_id"] == "AUTH-DB-001"
    assert events[0]["risk_score"] == 70


def test_multiple_events_persist(tmp_path):
    database = tmp_path / "test_soc.db"

    for attempts in [2, 8, 15]:
        result = process_authentication_log({
            "event_id": f"AUTH-{attempts}",
            "failed_attempts": attempts,
        })

        save_event(result, database)

    events = get_events(database)

    assert len(events) == 3

    scores = {event["risk_score"] for event in events}

    assert scores == {40, 70, 95}


def test_empty_database(tmp_path):
    database = tmp_path / "test_soc.db"

    events = get_events(database)

    assert events == []