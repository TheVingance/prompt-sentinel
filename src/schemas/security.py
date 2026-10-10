from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    HARMFUL_CONTENT = "harmful_content"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"


class SecurityIncidentResponse(BaseModel):
    error: str = "Request blocked by PromptSentinel AI Firewall"
    incident_id: str = Field(..., description="UUID para rastreamento no log de auditoria")
    category: ThreatCategory
    severity: ThreatSeverity
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
