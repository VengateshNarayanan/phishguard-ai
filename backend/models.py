"""
Pydantic data models and schemas for PhishGuard AI (Phase 2).
Provides strong type-safety and automatic validation for API requests,
extended with MCP tool evidence and high-level investigation steps.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ClassificationEnum(str, Enum):
    """Classification states for analyzed messages."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    SCAM = "SCAM"


class SeverityEnum(str, Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalyzeRequest(BaseModel):
    """Request payload sent to POST /analyze."""
    sender: str = Field(
        default="",
        description="Sender email address or display name (optional, but helpful for context)",
        examples=["security-alert@paypal-account-update.com"]
    )
    subject: str = Field(
        default="",
        description="Subject line of the email or message",
        examples=["URGENT: Your account has been suspended!"]
    )
    message: str = Field(
        ...,
        min_length=1,
        description="The full raw body text or headers of the email/message to be analyzed",
        examples=["Dear user, click this link immediately to verify your credentials: http://suspicious-link.ru/login"]
    )


class ToolEvidenceItem(BaseModel):
    """Individual MCP tool execution evidence item."""
    tool: str = Field(..., description="Name of the MCP tool invoked (e.g. analyze_url)")
    result: Dict[str, Any] = Field(..., description="Structured findings returned by the tool")


class AnalyzeResponse(BaseModel):
    """Response payload returned by POST /analyze with Phase 2 MCP extensions."""
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Estimated risk level from 0 (Completely Safe) to 100 (Immediate Threat)",
        examples=[92]
    )
    classification: ClassificationEnum = Field(
        ...,
        description="Primary security classification: SAFE, SUSPICIOUS, PHISHING, or SCAM",
        examples=[ClassificationEnum.PHISHING]
    )
    severity: SeverityEnum = Field(
        ...,
        description="Severity ranking: LOW, MEDIUM, HIGH, or CRITICAL",
        examples=[SeverityEnum.CRITICAL]
    )
    summary: str = Field(
        ...,
        description="Concise executive summary of the security findings",
        examples=["High-confidence phishing attempt impersonating PayPal with credential harvesting link."]
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Detailed bullet points explaining why this classification was chosen",
        examples=[
            "Artificial urgency used to induce panic and bypass critical thinking",
            "Suspicious external domain mismatched with official PayPal branding",
            "Request for credential entry on an unverified third-party page"
        ]
    )
    indicators: List[str] = Field(
        default_factory=list,
        description="Key threat indicators detected in the message",
        examples=[
            "Urgency / Fear manipulation",
            "Credential harvesting link",
            "Brand impersonation (PayPal)",
            "Unusual sender domain"
        ]
    )
    recommended_action: str = Field(
        ...,
        description="Actionable advice for the end-user or IT team",
        examples=["Do not click any links or provide credentials. Flag as phishing and report to IT Security."]
    )
    tool_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence collected from MCP tools (e.g. URL inspection, domain reputation, header verification)"
    )
    analysis_steps: List[str] = Field(
        default_factory=list,
        description="High-level timeline of investigation actions performed by the agent"
    )


class HealthResponse(BaseModel):
    """Response payload for GET /health."""
    status: str = Field(default="healthy", examples=["healthy"])


class McpStatusResponse(BaseModel):
    """Response payload for GET /mcp/status."""
    status: str = Field(default="connected", description="MCP server readiness state")
    tools: List[str] = Field(
        default_factory=lambda: ["analyze_url", "analyze_domain", "analyze_email_headers"],
        description="List of registered MCP tool names"
    )
    server_name: str = Field(default="phishguard-security-tools", description="MCP server identifier")
