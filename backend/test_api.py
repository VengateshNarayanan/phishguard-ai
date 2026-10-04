"""
Automated unit, integration, and security test suite for PhishGuard AI (Phase 2).
Covers:
- MCP server imports and tool discovery
- Static URL analyzer (normal, suspicious, and IP-address URLs)
- Domain analyzer (safe domains, suspicious TLDs, brand spoofing)
- Email header analyzer (mismatch, SPF, DKIM, DMARC failures)
- Security Agent coordination and selective tool activation
- Tool error handling resilience
- Phase 1 regression verification
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure DEMO_MODE is active during testing
os.environ["DEMO_MODE"] = "true"

# Ensure mcp_server is discoverable
MCP_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp_server"))
if MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, MCP_SERVER_DIR)

from main import app
from models import AnalyzeRequest, ClassificationEnum, SeverityEnum
from tools.url_analyzer import analyze_url
from tools.domain_analyzer import analyze_domain
from tools.email_header_analyzer import analyze_email_headers
from agent import SecurityAgent

client = TestClient(app)


# ============================================================================
# 1. MCP SERVER & COMPONENT TESTS
# ============================================================================

def test_mcp_server_import_and_discovery():
    """Verify MCP server startup and exposure of all 3 security tools."""
    from server import server as mcp_inst
    assert mcp_inst is not None
    assert mcp_inst.name == "phishguard-security-tools"
    # Ensure all three required tools are registered in the server
    tool_names = [tool.name for tool in mcp_inst._tool_manager.list_tools()]
    assert "analyze_url" in tool_names
    assert "analyze_domain" in tool_names
    assert "analyze_email_headers" in tool_names


def test_mcp_status_endpoint():
    """Verify GET /mcp/status endpoint returns connected status and tools list."""
    response = client.get("/mcp/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "connected"
    assert "analyze_url" in data["tools"]
    assert "analyze_domain" in data["tools"]
    assert "analyze_email_headers" in data["tools"]


# ============================================================================
# 2. URL ANALYZER TESTS
# ============================================================================

def test_url_analyzer_normal_url():
    """Verify static analysis on a legitimate HTTPS URL without threat indicators."""
    result = analyze_url("https://github.com/features/security")
    assert result["risk_level"] == "LOW"
    assert result["risk_score"] <= 25
    assert result["safe_to_visit"] is True
    assert any("Standard" in sig for sig in result["signals"])


def test_url_analyzer_suspicious_url():
    """Verify detection of plaintext HTTP, suspicious port, and credential keyword."""
    result = analyze_url("http://paypal-account-verify.ru:8080/login/update")
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 55
    assert result["safe_to_visit"] is False
    assert any("Insecure HTTP" in sig for sig in result["signals"])
    assert any("port" in sig.lower() for sig in result["signals"])
    assert any("credential" in sig.lower() for sig in result["signals"])


def test_url_analyzer_ip_address_url():
    """Verify detection of raw IP address hostname instead of domain name."""
    result = analyze_url("http://192.168.1.150/banking/auth")
    assert result["risk_score"] >= 45
    assert any("raw IP address" in sig for sig in result["signals"])
    assert result["safe_to_visit"] is False


# ============================================================================
# 3. DOMAIN ANALYZER TESTS
# ============================================================================

def test_domain_analyzer_safe_and_suspicious():
    """Verify domain analysis handles legitimate domains and flags high-risk TLDs and typosquats."""
    safe_res = analyze_domain("google.com")
    assert safe_res["risk_level"] == "LOW"
    assert safe_res["local_analysis"]["valid_syntax"] is True

    suspicious_res = analyze_domain("paypal-security-account-center.xyz")
    assert suspicious_res["risk_level"] in ("HIGH", "CRITICAL")
    assert any(".xyz" in sig for sig in suspicious_res["signals"])
    assert any("hyphen" in sig.lower() for sig in suspicious_res["signals"])
    assert any("paypal" in sig.lower() for sig in suspicious_res["signals"])
    assert suspicious_res["lookup_available"] is False


# ============================================================================
# 4. EMAIL HEADER ANALYZER TESTS
# ============================================================================

def test_email_header_analyzer_basic():
    """Verify basic header parsing and verify absent SPF/DKIM are marked NOT_PROVIDED."""
    raw_headers = """From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Team Sync
"""
    result = analyze_email_headers(raw_headers)
    assert result["from"] == "Alice <alice@example.com>"
    assert result["mismatch_detected"] is False
    assert result["spf"]["status"] == "NOT_PROVIDED"
    assert result["dkim"]["status"] == "NOT_PROVIDED"
    assert result["dmarc"]["status"] == "NOT_PROVIDED"


def test_email_header_analyzer_from_reply_to_mismatch():
    """Verify detection of From vs Reply-To domain spoofing/mismatch."""
    raw_headers = """From: Support <support@paypal.com>
Reply-To: Fraudster <phisher@evil-mailbox.net>
Subject: Account Update
"""
    result = analyze_email_headers(raw_headers)
    assert result["mismatch_detected"] is True
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert any("From vs Reply-To domain mismatch" in sig for sig in result["signals"])


def test_email_header_analyzer_spf_failure():
    """Verify detection of SPF authentication failure."""
    raw_headers = """From: billing@chase.com
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=chase.com;
Subject: Notice
"""
    result = analyze_email_headers(raw_headers)
    assert result["spf"]["status"] == "FAIL"
    assert any("SPF authentication failed" in sig for sig in result["signals"])


def test_email_header_analyzer_dkim_failure():
    """Verify detection of DKIM cryptographic verification failure."""
    raw_headers = """From: security@apple.com
Authentication-Results: mx.google.com; dkim=fail header.i=@apple.com;
Subject: Apple ID Reset
"""
    result = analyze_email_headers(raw_headers)
    assert result["dkim"]["status"] == "FAIL"
    assert any("DKIM cryptographic signature verification failed" in sig for sig in result["signals"])


def test_email_header_analyzer_dmarc_failure():
    """Verify detection of DMARC alignment failure."""
    raw_headers = """From: alert@wellsfargo.com
Authentication-Results: mx.google.com; dmarc=fail action=quarantine;
Subject: Security Verification
"""
    result = analyze_email_headers(raw_headers)
    assert result["dmarc"]["status"] == "FAIL"
    assert any("DMARC policy alignment failed" in sig for sig in result["signals"])


# ============================================================================
# 5. SECURITY AGENT COORDINATION TESTS
# ============================================================================

def test_agent_without_tools_on_safe_message():
    """Verify intelligent agent behavior: No URLs or headers -> bypasses tool calls."""
    payload = {
        "sender": "david@internal.company",
        "subject": "Lunch Today",
        "message": "Hey team, anyone want to grab burritos at 12:30?"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationEnum.SAFE.value
    assert data["risk_score"] <= 25
    # Verify analysis_steps records that tools were bypassed
    assert any("bypassed URL Analyzer" in step for step in data["analysis_steps"])
    assert any("bypassed Header Analyzer" in step for step in data["analysis_steps"])


def test_agent_with_suspicious_url():
    """Verify agent detects candidate URL and incorporates MCP URL tool evidence."""
    payload = {
        "sender": "security-alert@service-account.com",
        "subject": "Urgent Security Verification",
        "message": "Please confirm your password immediately at http://192.168.1.1/login or your account is suspended."
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationEnum.PHISHING.value
    # Verify tool evidence was recorded
    assert any(ev["tool"] == "analyze_url" for ev in data["tool_evidence"])
    # Verify investigation step is documented
    assert any("Invoking MCP URL Analyzer" in step for step in data["analysis_steps"])


def test_agent_mcp_tool_failure_handling():
    """Verify agent resilience: If an MCP tool fails, analysis continues without crashing."""
    import asyncio
    agent = SecurityAgent()

    # Simulate tool error
    async def mock_fail(tool_name, arguments):
        raise ConnectionResetError("Simulated MCP transport error")

    agent.call_mcp_tool = mock_fail

    request = AnalyzeRequest(
        sender="notice@test.com",
        subject="Notice",
        message="Check this link: http://example-suspicious-site.com/auth"
    )

    result = asyncio.run(agent.analyze(request))
    assert result is not None
    # Check that tool status was recorded as unavailable
    assert any(ev.get("status") == "unavailable" for ev in result.tool_evidence)
    # Check that analysis completed with high-level steps
    assert any("unavailable" in step for step in result.analysis_steps)


# ============================================================================
# 6. PHASE 1 REGRESSION TESTS (Ensures existing functionality is preserved)
# ============================================================================

def test_root_endpoint():
    """Verify GET / returns 200 with API status information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "PhishGuard" in data["name"]
    assert "endpoints" in data


def test_health_endpoint():
    """Verify GET /health returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_analyze_empty_message_validation():
    """Verify that an empty message body produces a 422 Unprocessable Entity error."""
    payload = {"sender": "test@example.com", "subject": "Hello", "message": ""}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_analyze_missing_message_field():
    """Verify that omitting the required message field fails validation with 422."""
    payload = {"sender": "test@example.com", "subject": "Missing body"}
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422


def test_analyze_safe_email():
    """Verify that standard legitimate business communication is classified as SAFE."""
    payload = {
        "sender": "sarah.jenkins@company.internal",
        "subject": "Quarterly Planning Deck Review",
        "message": (
            "Hi team, please find time to review the Q3 strategy slides before our "
            "all-hands sync on Thursday. Feel free to leave comments directly on the shared drive."
        )
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationEnum.SAFE.value
    assert data["severity"] == SeverityEnum.LOW.value
    assert data["risk_score"] <= 25


def test_analyze_phishing_email():
    """Verify that a credential-harvesting, urgent email is classified as PHISHING."""
    payload = {
        "sender": "security-alert@service-paypal-verify.com",
        "subject": "URGENT: Your account has been suspended!",
        "message": (
            "We have detected unauthorized activity on your PayPal account. "
            "Your account is suspended immediately. Click here to verify your account "
            "and confirm your identity: http://paypal-security-check.ru/login. "
            "Failure to act within 24 hours will result in permanent deletion."
        )
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationEnum.PHISHING.value
    assert data["severity"] in [SeverityEnum.HIGH.value, SeverityEnum.CRITICAL.value]
    assert data["risk_score"] >= 70


def test_analyze_scam_email():
    """Verify that an advance-fee / crypto scam message is classified as SCAM."""
    payload = {
        "sender": "barrister.kofi@un-reward-dept.org",
        "subject": "CONGRATULATIONS: You won 5 million dollars lottery!",
        "message": (
            "Dear Beneficiary, You have won 5 million dollars in the international lottery promo. "
            "To claim your prize, please send 500 dollars via wire transfer or cryptocurrency bitcoin "
            "for administrative processing fees."
        )
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationEnum.SCAM.value
    assert data["severity"] == SeverityEnum.CRITICAL.value
    assert data["risk_score"] >= 80


def test_analyze_suspicious_email():
    """Verify that vague cold-solicitation with unverified tracking links is classified as SUSPICIOUS."""
    payload = {
        "sender": "dispatch@express-shipment-notice.com",
        "subject": "Action required: Undelivered package #88291",
        "message": (
            "Your parcel could not be delivered today. Action required to schedule delivery. "
            "Please check the tracking link: https://shipment-tracking-review-hub.net/package"
        )
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in [ClassificationEnum.SUSPICIOUS.value, ClassificationEnum.PHISHING.value]
    assert data["risk_score"] > 25
