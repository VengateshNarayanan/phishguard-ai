"""
PhishGuard AI - AI Service Layer.
Integrates with the Google Gemini API using the modern `google-genai` SDK.
Analyzes emails/messages for phishing, scam, and social engineering indicators.
"""

import os
import re
import json
import logging
from typing import Optional
from dotenv import load_dotenv
from fastapi import HTTPException

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ClassificationEnum,
    SeverityEnum,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishguard.ai_service")

# Load environment variables from .env file
load_dotenv()

# System instruction instructing Gemini to act as a cybersecurity analyst
SYSTEM_INSTRUCTION = """You are PhishGuard AI, an expert cybersecurity phishing and threat intelligence analyst.
Your mission is to perform deep inspection of suspicious emails, SMS messages, and digital communications to detect phishing attacks, social engineering, fraudulent scams, and malicious intent.

You must rigorously analyze the communication for:
1. Urgency or fear manipulation (e.g. "immediate action required", "account deleted in 24h")
2. Suspicious requests for credentials or passwords
3. Financial requests (wire transfers, crypto, gift cards, invoices)
4. Account suspension or legal threats
5. Impersonation of trusted brands, organizations, colleagues, or executives
6. Suspicious, mismatched, or deceptive URLs / domains
7. Social engineering and emotional manipulation
8. Grammar anomalies, awkward phrasing, or non-native phrasing common in mass phishing
9. Requests for sensitive information (SSN, credit card, PIN, 2FA codes)
10. Unusual sender behavior or discrepancies between display name and email domain

Evaluation Rules:
- risk_score: 0-25 (SAFE), 26-55 (SUSPICIOUS), 56-85 (PHISHING), 86-100 (SCAM / CRITICAL PHISHING)
- classification: Exactly one of ["SAFE", "SUSPICIOUS", "PHISHING", "SCAM"]
- severity: Exactly one of ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
- summary: A concise 1-2 sentence executive assessment
- reasons: Bullet points detailing the rationale behind your assessment
- indicators: List of specific threat flags identified (e.g. "Credential Harvesting", "Brand Impersonation")
- recommended_action: Practical, direct guidance for the recipient

You must output ONLY valid JSON adhering strictly to the required schema. Do not include markdown code block backticks if raw JSON is requested.
"""


def get_gemini_client():
    """
    Initializes and returns a Google GenAI client using the GEMINI_API_KEY environment variable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key.strip() in ("", "your_gemini_api_key_here"):
        return None

    try:
        from google import genai
        return genai.Client(api_key=api_key)
    except Exception as e:
        logger.error(f"Error initializing Google GenAI client: {e}")
        return None


def run_heuristic_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Local heuristic fallback analyzer used when DEMO_MODE=true or when Gemini API key is not configured.
    Provides realistic security assessments for safe, suspicious, phishing, and scam messages.
    """
    text = f"{request.sender} {request.subject} {request.message}".lower()
    
    # Pattern matching for common phishing/scam signals
    phishing_keywords = [
        "urgent", "immediately", "account suspended", "verify your account",
        "confirm your identity", "password reset", "security alert",
        "unauthorized activity", "click here", "login to", "update billing"
    ]
    scam_keywords = [
        "lottery", "prize", "won", "million dollars", "inheritance", "cryptocurrency",
        "crypto", "bitcoin", "wire transfer", "western union", "gift card",
        "guaranteed return", "rich", "beneficiary", "diplomat"
    ]
    suspicious_keywords = [
        "invoice attached", "unusual sign-in", "action required", "undelivered package",
        "tracking link", "overdue payment", "limited time"
    ]
    
    found_phishing = [kw for kw in phishing_keywords if kw in text]
    found_scam = [kw for kw in scam_keywords if kw in text]
    found_suspicious = [kw for kw in suspicious_keywords if kw in text]
    
    url_pattern = re.compile(r"https?://\S+|www\.\S+")
    has_urls = bool(url_pattern.search(request.message))
    
    # 1. SCAM assessment
    if len(found_scam) >= 2 or ("crypto" in text and ("invest" in text or "send" in text)):
        return AnalyzeResponse(
            risk_score=94,
            classification=ClassificationEnum.SCAM,
            severity=SeverityEnum.CRITICAL,
            summary="High-probability financial scam detected exploiting unrealistic promises or fraudulent transfers.",
            reasons=[
                "Contains keywords indicative of financial fraud or advance-fee scams.",
                f"Detected scam triggers: {', '.join(found_scam[:4])}.",
                "Solicits high-risk financial interaction, gift cards, or cryptocurrency."
            ],
            indicators=[
                "Financial Fraud Pattern",
                "Advance-Fee / Lottery Lure",
                "High-Risk Transaction Request"
            ],
            recommended_action="Do not respond, do not send any funds or gift cards. Immediately block and report the sender."
        )
    
    # 2. PHISHING assessment
    if len(found_phishing) >= 2 or ("verify" in text and has_urls) or "suspend" in text:
        return AnalyzeResponse(
            risk_score=88,
            classification=ClassificationEnum.PHISHING,
            severity=SeverityEnum.HIGH,
            summary="Urgent security alert attempting credential harvesting or account compromise.",
            reasons=[
                "Message employs artificial urgency and fear manipulation regarding account status.",
                f"Detected phishing triggers: {', '.join(found_phishing[:4])}.",
                "Directs recipient to external links for credential or account verification."
            ],
            indicators=[
                "Artificial Urgency / Threat Manipulation",
                "Credential Harvesting Link",
                "Account Suspension Threat",
                "Brand Impersonation Risk"
            ],
            recommended_action="Do NOT click any embedded links. Navigate to the official service website directly via your browser to inspect account status."
        )

    # 3. SUSPICIOUS assessment
    if found_suspicious or has_urls or len(found_phishing) == 1:
        return AnalyzeResponse(
            risk_score=48,
            classification=ClassificationEnum.SUSPICIOUS,
            severity=SeverityEnum.MEDIUM,
            summary="Message exhibits questionable elements requiring caution before interacting.",
            reasons=[
                "Contains vague calls to action or unexpected tracking/invoice references.",
                "External links or attachments present without established context.",
                "Sender authenticity cannot be verified from available headers."
            ],
            indicators=[
                "Unsolicited Call-to-Action",
                "External Link Inspection Required",
                "Potential Cold Outreach / Spoofing"
            ],
            recommended_action="Exercise caution. Verify the sender's identity through an independent, trusted channel before clicking links."
        )

    # 4. SAFE assessment
    return AnalyzeResponse(
        risk_score=8,
        classification=ClassificationEnum.SAFE,
        severity=SeverityEnum.LOW,
        summary="No significant phishing, scam, or social engineering indicators were detected.",
        reasons=[
            "No coercive urgency or high-pressure tactics identified.",
            "No credential harvesting or suspicious payment demands found.",
            "Content and tone appear consistent with standard, legitimate correspondence."
        ],
        indicators=[
            "Standard Business/Personal Tone",
            "No Malicious URLs Detected",
            "No Coercive Language"
        ],
        recommended_action="No immediate threat detected. Standard operational security practices still apply."
    )


def analyze_message(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Main analysis entry point.
    Attempts analysis via Google Gemini API using `google-genai`.
    Falls back to heuristic engine if DEMO_MODE is true or if API key is not configured.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    # If key is missing
    if not api_key or api_key.strip() in ("", "your_gemini_api_key_here"):
        if demo_mode:
            logger.info("GEMINI_API_KEY not configured, but DEMO_MODE=true. Running local heuristic analyzer.")
            return run_heuristic_analysis(request)
        else:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Gemini API key is not configured. "
                    "Please set your GEMINI_API_KEY in the 'backend/.env' file, "
                    "or set DEMO_MODE=true for testing without an API key."
                )
            )

    # If API key is present, invoke Gemini using google-genai
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

        user_content = f"""Please perform a thorough security analysis on this message:

SENDER: {request.sender or '(Not provided)'}
SUBJECT: {request.subject or '(Not provided)'}
MESSAGE BODY:
{request.message}
"""

        # Enforce structured JSON output matching AnalyzeResponse schema
        response = client.models.generate_content(
            model=model_name,
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                response_schema=AnalyzeResponse,
                temperature=0.1,
            )
        )

        if not response or not response.text:
            raise ValueError("Empty response received from Gemini API.")

        # Clean potential markdown formatting just in case
        raw_text = response.text.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

        # Validate structured JSON into Pydantic model
        result = AnalyzeResponse.model_validate_json(raw_text)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Gemini API call failed: {e}", exc_info=True)
        # If in demo mode or fallback is acceptable on error
        if demo_mode:
            logger.warning("Gemini invocation failed; falling back to heuristic engine because DEMO_MODE=true.")
            return run_heuristic_analysis(request)
        
        # Provide clean, actionable error to the client
        raise HTTPException(
            status_code=502,
            detail=f"AI analysis failed while contacting Google Gemini API: {str(e)}"
        )
