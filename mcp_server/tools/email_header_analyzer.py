"""
PhishGuard AI - MCP Email Header Analyzer Tool.
Parses RFC 822 / MIME email headers or structured header dictionaries.
Detects From vs Reply-To mismatches, SPF/DKIM/DMARC authentication failures,
Return-Path anomalies, and suspicious mail relay hops.
"""

import re
from email.utils import parseaddr


def parse_raw_headers(header_input: str | dict) -> dict:
    """Converts a raw multiline header string or dict into a normalized lowercase dict."""
    if isinstance(header_input, dict):
        return {str(k).lower(): str(v) for k, v in header_input.items()}

    headers = {}
    if not isinstance(header_input, str):
        return headers

    lines = header_input.splitlines()
    current_key = None
    current_val = []

    for line in lines:
        # Header continuation (starts with space or tab)
        if (line.startswith(" ") or line.startswith("\t")) and current_key:
            current_val.append(line.strip())
        elif ":" in line:
            if current_key:
                headers[current_key] = " ".join(current_val)
            parts = line.split(":", 1)
            current_key = parts[0].strip().lower()
            current_val = [parts[1].strip()]
        else:
            continue

    if current_key:
        headers[current_key] = " ".join(current_val)

    return headers


def extract_domain(email_str: str) -> str:
    """Extracts the domain portion of an email address string."""
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    return ""


def analyze_email_headers(headers: str | dict) -> dict:
    """
    Inspects email headers for spoofing, authentication failures, and relay anomalies.
    
    Args:
        headers: Multiline string containing RFC 822 email headers, or dictionary of headers.
        
    Returns:
        Structured dictionary with parsed headers, authentication results, signals, and risk_level.
    """
    parsed = parse_raw_headers(headers)
    signals = []
    score = 0

    from_header = parsed.get("from", "")
    reply_to_header = parsed.get("reply-to", "")
    return_path_header = parsed.get("return-path", "")
    auth_results = parsed.get("authentication-results", "")
    received_header = parsed.get("received", "")

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to_header)
    return_path_domain = extract_domain(return_path_header)

    # 1. From vs Reply-To Mismatch Detection
    mismatch_detected = False
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        mismatch_detected = True
        score += 45
        signals.append(
            f"From vs Reply-To domain mismatch: From says '{from_domain}', but Reply-To redirects to '{reply_to_domain}'"
        )

    # 2. Return-Path Mismatch Detection
    if from_domain and return_path_domain and from_domain != return_path_domain:
        score += 25
        signals.append(
            f"Return-Path domain mismatch: Sender '{from_domain}' differs from Return-Path '{return_path_domain}'"
        )

    # 3. SPF Authentication Analysis
    spf_data = {"present": False, "status": "NOT_PROVIDED", "detail": ""}
    spf_pattern = r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b"
    spf_match = re.search(spf_pattern, auth_results, re.IGNORECASE) or re.search(spf_pattern, str(parsed), re.IGNORECASE)

    if spf_match:
        spf_status = spf_match.group(1).lower()
        spf_data = {"present": True, "status": spf_status.upper(), "detail": spf_match.group(0)}
        if spf_status in ("fail", "permerror"):
            score += 40
            signals.append(f"SPF authentication failed: {spf_match.group(0)}")
        elif spf_status == "softfail":
            score += 20
            signals.append(f"SPF softfail detected: {spf_match.group(0)}")
        elif spf_status == "pass":
            signals.append("SPF authentication passed")
    else:
        signals.append("SPF record not provided in supplied headers")

    # 4. DKIM Authentication Analysis
    dkim_data = {"present": False, "status": "NOT_PROVIDED", "detail": ""}
    dkim_pattern = r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b"
    dkim_match = re.search(dkim_pattern, auth_results, re.IGNORECASE) or re.search(dkim_pattern, str(parsed), re.IGNORECASE)

    if dkim_match:
        dkim_status = dkim_match.group(1).lower()
        dkim_data = {"present": True, "status": dkim_status.upper(), "detail": dkim_match.group(0)}
        if dkim_status in ("fail", "permerror"):
            score += 40
            signals.append(f"DKIM cryptographic signature verification failed: {dkim_match.group(0)}")
        elif dkim_status == "pass":
            signals.append("DKIM signature verified")
    else:
        signals.append("DKIM signature header not provided")

    # 5. DMARC Authentication Analysis
    dmarc_data = {"present": False, "status": "NOT_PROVIDED", "detail": ""}
    dmarc_pattern = r"\bdmarc=(pass|fail|temperror|permerror|none)\b"
    dmarc_match = re.search(dmarc_pattern, auth_results, re.IGNORECASE) or re.search(dmarc_pattern, str(parsed), re.IGNORECASE)

    if dmarc_match:
        dmarc_status = dmarc_match.group(1).lower()
        dmarc_data = {"present": True, "status": dmarc_status.upper(), "detail": dmarc_match.group(0)}
        if dmarc_status in ("fail", "permerror"):
            score += 50
            signals.append(f"DMARC policy alignment failed: {dmarc_match.group(0)}")
        elif dmarc_status == "pass":
            signals.append("DMARC alignment passed")
    else:
        signals.append("DMARC evaluation header not provided")

    # 6. Suspicious Relay in Received Hops
    if received_header and ("unverified" in received_header.lower() or "dynamic" in received_header.lower()):
        score += 20
        signals.append("Suspicious relay or unverified IP found in Received hop trace")

    # Compute overall risk level
    risk_score = min(100, max(0, score))
    if risk_score >= 65:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "from": from_header,
        "reply_to": reply_to_header,
        "return_path": return_path_header,
        "mismatch_detected": mismatch_detected,
        "spf": spf_data,
        "dkim": dkim_data,
        "dmarc": dmarc_data,
        "signals": signals,
        "risk_level": risk_level,
        "risk_score": risk_score
    }
