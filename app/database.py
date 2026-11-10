import json
import sqlite3
from pathlib import Path

from app.pipeline import PipelineResult


DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "soc_events.db"


def initialize_database(db_path=DATABASE_PATH):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                analysis_data TEXT NOT NULL,
                explanation_data TEXT NOT NULL
            )
            """
        )


def save_event(result: PipelineResult, db_path=DATABASE_PATH):
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO security_events (
                event_id,
                timestamp,
                severity,
                classification,
                risk_score,
                event_data,
                analysis_data,
                explanation_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.event.event_id,
                result.event.timestamp.isoformat(),
                result.event.severity.value,
                result.analysis.classification,
                result.analysis.risk_score,
                result.event.model_dump_json(),
                result.analysis.model_dump_json(),
                result.explanation.model_dump_json(),
            ),
        )


def get_events(db_path=DATABASE_PATH):
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]