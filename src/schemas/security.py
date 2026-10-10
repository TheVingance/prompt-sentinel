from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    HARMFUL_CONTENT = "harmful_content"


class SecurityIncidentResponse(BaseModel):
    error: str = "Request blocked by PromptSentinel AI Firewall"
    incident_id: str = Field(..., description="UUID para rastreamento no log de auditoria")
    category: ThreatCategory
    severity: ThreatSeverity
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
