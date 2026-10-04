"""
PhishGuard AI - Security Agent (Phase 2).
Coordinates Gemini AI reasoning with Model Context Protocol (MCP) security tools.
Executes multi-step investigation: initial triage, selective tool invocation,
evidence aggregation, and AI reassessment.
"""

import os
import sys
import re
import json
import logging
import asyncio
from typing import List, Dict, Any, Optional

# Add mcp_server directory to python path
MCP_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp_server"))
if MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, MCP_SERVER_DIR)

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ClassificationEnum,
    SeverityEnum,
)
from ai_service import (
    get_gemini_client,
    run_heuristic_analysis,
    SYSTEM_INSTRUCTION,
)

logger = logging.getLogger("phishguard.agent")

# Import the MCP server instance
try:
    from server import server as mcp_server
except ImportError as e:
    logger.warning(f"Could not directly import MCP server: {e}")
    mcp_server = None


class SecurityAgent:
    """
    Intelligent Security Agent that inspects incoming communications,
    selects appropriate MCP tools based on content indicators, collects empirical evidence,
    and performs AI reassessment.
    """

    def __init__(self):
        self.server = mcp_server

    async def call_mcp_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Invokes an MCP tool safely through the MCP server interface.
        Handles errors gracefully without crashing the analysis.
        """
        if not self.server:
            raise RuntimeError("MCP server is not initialized or unavailable.")

        try:
            res = await self.server.call_tool(tool_name, arguments)
            # Parse output from MCP CallToolResult
            if hasattr(res, "structured_content") and res.structured_content:
                return res.structured_content
            if hasattr(res, "content") and res.content and len(res.content) > 0:
                text_content = res.content[0].text
                try:
                    return json.loads(text_content)
                except Exception:
                    return {"raw_output": text_content}
            return {"status": "completed", "output": str(res)}
        except Exception as e:
            logger.error(f"Error calling MCP tool '{tool_name}': {e}", exc_info=True)
            raise

    def extract_urls(self, text: str) -> List[str]:
        """Extracts candidate URLs from message text."""
        url_regex = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
        found = url_regex.findall(text)
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for u in found:
            clean = u.rstrip(".,;!?)")
            if clean not in seen:
                seen.add(clean)
                unique_urls.append(clean)
        return unique_urls

    def extract_domains_from_urls(self, urls: List[str]) -> List[str]:
        """Extracts domain hostnames from a list of URLs."""
        domains = []
        for u in urls:
            try:
                # Strip scheme if present
                clean = re.sub(r"^[a-zA-Z]+://", "", u)
                domain = clean.split("/")[0].split(":")[0].strip().lower()
                if domain and domain not in domains:
                    domains.append(domain)
            except Exception:
                continue
        return domains

    def extract_sender_domain(self, sender: str) -> str:
        """Extracts domain from sender string."""
        if "@" in sender:
            parts = sender.split("@")
            domain = parts[-1].rstrip(">").strip().lower()
            return domain
        return ""

    def detect_email_headers(self, message: str) -> bool:
        """Checks if the message text appears to contain raw RFC 822 email headers."""
        header_triggers = [
            "received:", "authentication-results:", "dkim-signature:",
            "return-path:", "message-id:", "x-mailer:", "reply-to:"
        ]
        text_lower = message.lower()
        matches = sum(1 for trigger in header_triggers if trigger in text_lower)
        return matches >= 2 or "authentication-results:" in text_lower or ("from:" in text_lower and "reply-to:" in text_lower)

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        """
        Full Agentic Investigation Workflow:
        1. Receive email/message.
        2. Perform initial analysis & candidate extraction.
        3. Decide which security tools are required (Agentic Tool Selection).
        4. Invoke MCP tools & collect empirical evidence.
        5. Perform AI Reassessment with Gemini or heuristic engine.
        6. Return final response with tool evidence and high-level steps.
        """
        analysis_steps: List[str] = []
        tool_evidence: List[Dict[str, Any]] = []

        analysis_steps.append("Investigation initiated: Received message for multi-vector threat inspection")

        # Combine text for entity extraction
        full_content = f"{request.sender}\n{request.subject}\n{request.message}"

        # 1. Candidate Entity Extraction
        candidate_urls = self.extract_urls(full_content)
        sender_domain = self.extract_sender_domain(request.sender)
        has_headers = self.detect_email_headers(request.message)

        analysis_steps.append(
            f"Initial triage completed: Identified {len(candidate_urls)} candidate URL(s), "
            f"sender domain '{sender_domain or 'None'}', and headers_present={has_headers}"
        )

        # 2. Intelligent Tool Selection & Invocation
        # Tool 1: URL Analyzer
        if candidate_urls:
            target_url = candidate_urls[0]  # Inspect primary target
            analysis_steps.append(f"Suspicious link candidate detected: Invoking MCP URL Analyzer for '{target_url}'")
            try:
                url_result = await self.call_mcp_tool("analyze_url", {"url": target_url})
                tool_evidence.append({
                    "tool": "analyze_url",
                    "target": target_url,
                    "result": url_result
                })
                analysis_steps.append(f"URL static analysis completed: Risk evaluated as {url_result.get('risk_level', 'UNKNOWN')}")
            except Exception as e:
                tool_evidence.append({
                    "tool": "analyze_url",
                    "target": target_url,
                    "status": "unavailable",
                    "error": str(e)
                })
                analysis_steps.append("MCP URL Analyzer was unavailable; proceeding with available heuristics")
        else:
            analysis_steps.append("No external URLs detected; bypassed URL Analyzer tool")

        # Tool 2: Domain Analyzer
        candidate_domain = sender_domain
        if not candidate_domain and candidate_urls:
            url_domains = self.extract_domains_from_urls(candidate_urls)
            if url_domains:
                candidate_domain = url_domains[0]

        # Call domain tool if candidate domain exists and is not an obvious generic safe host
        if candidate_domain:
            analysis_steps.append(f"Evaluating candidate domain: Invoking MCP Domain Analyzer on '{candidate_domain}'")
            try:
                domain_result = await self.call_mcp_tool("analyze_domain", {"domain": candidate_domain})
                tool_evidence.append({
                    "tool": "analyze_domain",
                    "target": candidate_domain,
                    "result": domain_result
                })
                analysis_steps.append(f"Domain reputation check completed: Risk evaluated as {domain_result.get('risk_level', 'UNKNOWN')}")
            except Exception as e:
                tool_evidence.append({
                    "tool": "analyze_domain",
                    "target": candidate_domain,
                    "status": "unavailable",
                    "error": str(e)
                })
                analysis_steps.append("MCP Domain Analyzer was unavailable; proceeding with available heuristics")
        else:
            analysis_steps.append("No independent domain candidate detected; bypassed Domain Analyzer tool")

        # Tool 3: Email Header Analyzer
        if has_headers:
            analysis_steps.append("Raw email headers detected: Invoking MCP Email Header Analyzer")
            try:
                header_result = await self.call_mcp_tool("analyze_email_headers", {"headers": request.message})
                tool_evidence.append({
                    "tool": "analyze_email_headers",
                    "result": header_result
                })
                analysis_steps.append(
                    f"Email header analysis completed: Authentication risk evaluated as {header_result.get('risk_level', 'UNKNOWN')}"
                )
            except Exception as e:
                tool_evidence.append({
                    "tool": "analyze_email_headers",
                    "status": "unavailable",
                    "error": str(e)
                })
                analysis_steps.append("MCP Email Header Analyzer was unavailable; proceeding with available heuristics")
        else:
            analysis_steps.append("No raw RFC 822 email headers detected; bypassed Header Analyzer tool")

        # 3. AI Reassessment
        demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")
        api_key = os.getenv("GEMINI_API_KEY")

        if api_key and api_key.strip() not in ("", "your_gemini_api_key_here") and not demo_mode:
            analysis_steps.append("Submitting combined message content and MCP tool evidence to Gemini for AI Reassessment")
            try:
                final_response = await self._run_gemini_reassessment(request, tool_evidence)
                final_response.tool_evidence = tool_evidence
                analysis_steps.append("Final threat intelligence assessment generated by Gemini Security Model")
                final_response.analysis_steps = analysis_steps
                return final_response
            except Exception as e:
                logger.error(f"Gemini reassessment failed: {e}", exc_info=True)
                analysis_steps.append(f"Gemini API request failed ({e}); falling back to local heuristic synthesis")

        # Fallback / DEMO_MODE heuristic reassessment
        analysis_steps.append("Running local threat intelligence synthesis with collected MCP tool evidence")
        final_response = self._synthesize_heuristic_with_tools(request, tool_evidence)
        analysis_steps.append("Final risk assessment completed successfully")
        final_response.analysis_steps = analysis_steps
        final_response.tool_evidence = tool_evidence

        return final_response

    async def _run_gemini_reassessment(self, request: AnalyzeRequest, tool_evidence: List[dict]) -> AnalyzeResponse:
        """Invokes Gemini with both the original message and collected MCP tool evidence."""
        from google import genai
        from google.genai import types

        api_key = os.getenv("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

        evidence_summary = json.dumps(tool_evidence, indent=2)

        prompt = f"""You are PhishGuard AI, an expert cybersecurity threat intelligence analyst.
Perform a thorough FINAL THREAT ASSESSMENT synthesizing BOTH the message content and empirical tool evidence collected by your MCP tools.

SENDER: {request.sender or '(Not provided)'}
SUBJECT: {request.subject or '(Not provided)'}
MESSAGE BODY:
{request.message}

EMPIRICAL MCP SECURITY EVIDENCE:
{evidence_summary}

Instructions:
1. Re-evaluate your initial impression in light of the static URL signals, domain reputation, and email header authentication results.
2. If tool evidence reveals IP hostnames, suspicious ports, credential harvesting paths, or SPF/DKIM/DMARC failures, elevate the risk accordingly.
3. If tool evidence proves legitimate structures and no deceptive signals exist, lower the risk.
4. Output ONLY valid JSON adhering strictly to the AnalyzeResponse schema.
"""

        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                response_schema=AnalyzeResponse,
                temperature=0.1,
            )
        )

        raw_text = response.text.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

        return AnalyzeResponse.model_validate_json(raw_text.strip())

    def _synthesize_heuristic_with_tools(self, request: AnalyzeRequest, tool_evidence: List[dict]) -> AnalyzeResponse:
        """
        Synthesizes the base heuristic analysis with the empirical findings from MCP tools.
        Ensures consistent, deterministic results when DEMO_MODE=true.
        """
        base = run_heuristic_analysis(request)

        score = base.risk_score
        extra_reasons = list(base.reasons)
        extra_indicators = list(base.indicators)

        # Inspect evidence from URL Analyzer
        for ev in tool_evidence:
            tool_name = ev.get("tool")
            res = ev.get("result", {})

            if tool_name == "analyze_url":
                url_risk = res.get("risk_level", "LOW")
                url_score = res.get("risk_score", 0)
                signals = res.get("signals", [])

                if url_risk in ("HIGH", "CRITICAL"):
                    score = max(score, min(100, score + 25, url_score))
                    extra_indicators.append(f"MCP URL Alert: {url_risk} Risk Link")
                    for sig in signals[:2]:
                        extra_reasons.append(f"URL Analysis: {sig}")

            elif tool_name == "analyze_domain":
                dom_risk = res.get("risk_level", "LOW")
                signals = res.get("signals", [])

                if dom_risk in ("HIGH", "CRITICAL"):
                    score = max(score, 75)
                    extra_indicators.append(f"MCP Domain Alert: {dom_risk} Risk Domain")
                    for sig in signals[:2]:
                        extra_reasons.append(f"Domain Analysis: {sig}")

            elif tool_name == "analyze_email_headers":
                mismatch = res.get("mismatch_detected", False)
                spf = res.get("spf", {}).get("status", "")
                dkim = res.get("dkim", {}).get("status", "")
                dmarc = res.get("dmarc", {}).get("status", "")
                signals = res.get("signals", [])

                if mismatch:
                    score = max(score, 85)
                    extra_indicators.append("From / Reply-To Header Mismatch")
                    extra_reasons.append("Email Header Analysis: Reply-To points to an external unverified destination.")

                if spf in ("FAIL", "PERMERROR") or dkim in ("FAIL", "PERMERROR") or dmarc in ("FAIL", "PERMERROR"):
                    score = max(score, 90)
                    extra_indicators.append("Email Authentication Failure (SPF/DKIM/DMARC)")
                    extra_reasons.append(f"Email Header Analysis: Cryptographic authentication failed (SPF={spf}, DKIM={dkim}, DMARC={dmarc}).")

        # Re-derive classification and severity based on combined score and base findings
        score = min(100, max(0, score))
        if base.classification == ClassificationEnum.SCAM:
            classification = ClassificationEnum.SCAM
            severity = SeverityEnum.CRITICAL
        elif score >= 85:
            classification = ClassificationEnum.PHISHING
            severity = SeverityEnum.CRITICAL
        elif score >= 55:
            classification = ClassificationEnum.PHISHING
            severity = SeverityEnum.HIGH
        elif score >= 25:
            classification = ClassificationEnum.SUSPICIOUS
            severity = SeverityEnum.MEDIUM
        else:
            classification = ClassificationEnum.SAFE
            severity = SeverityEnum.LOW

        # Remove duplicate indicators/reasons
        unique_indicators = list(dict.fromkeys(extra_indicators))
        unique_reasons = list(dict.fromkeys(extra_reasons))

        summary = base.summary
        if any(ev.get("tool") == "analyze_url" and ev.get("result", {}).get("risk_level") in ("HIGH", "CRITICAL") for ev in tool_evidence):
            summary = "Empirical URL static analysis detected high-risk link attributes matching known phishing campaigns."
        elif any(ev.get("tool") == "analyze_email_headers" and ev.get("result", {}).get("mismatch_detected") for ev in tool_evidence):
            summary = "Critical email header spoofing detected: Sender address is forged to misdirect replies."

        return AnalyzeResponse(
            risk_score=score,
            classification=classification,
            severity=severity,
            summary=summary,
            reasons=unique_reasons,
            indicators=unique_indicators,
            recommended_action=base.recommended_action,
            tool_evidence=tool_evidence,
            analysis_steps=[]
        )


# Global agent instance
security_agent = SecurityAgent()


async def analyze_with_agent(request: AnalyzeRequest) -> AnalyzeResponse:
    """Entry point for FastAPI to invoke the Security Agent."""
    return await security_agent.analyze(request)
