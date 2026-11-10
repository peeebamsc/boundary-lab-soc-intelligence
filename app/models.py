from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    PRIVILEGE = "privilege"
    CLOUD = "cloud"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime
    category: EventCategory
    source: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Severity
    raw_log: dict[str, Any] = Field(default_factory=dict)


class EventAnalysis(BaseModel):
    event_id: str
    classification: str
    risk_score: int = Field(ge=0, le=100)
    explanation: str
    recommended_action: str