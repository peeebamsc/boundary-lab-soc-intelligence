from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import SecurityEvent, EventCategory, Severity


class AuthenticationLog(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(
        default="AUTH-UNKNOWN",
        min_length=1,
    )

    source: str = Field(
        default="synthetic-auth-server",
        min_length=1,
    )

    failed_attempts: int = Field(
        default=0,
        ge=0,
        le=100000,
        strict=True,
    )


def analyze_authentication_log(
    log: dict[str, Any],
) -> SecurityEvent:

    validated = AuthenticationLog.model_validate(log)

    failed_attempts = validated.failed_attempts

    if failed_attempts >= 10:
        severity = Severity.CRITICAL
        description = "Potential brute-force authentication activity"

    elif failed_attempts >= 5:
        severity = Severity.HIGH
        description = "Multiple failed authentication attempts"

    elif failed_attempts >= 1:
        severity = Severity.MEDIUM
        description = "Failed authentication attempt detected"

    else:
        severity = Severity.LOW
        description = "No failed authentication attempts detected"

    return SecurityEvent(
        event_id=validated.event_id,
        timestamp=datetime.now(timezone.utc),
        category=EventCategory.AUTHENTICATION,
        source=validated.source,
        description=description,
        severity=severity,
        raw_log=validated.model_dump(),
    )