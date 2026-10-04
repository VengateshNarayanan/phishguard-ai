"""
PhishGuard AI - MCP URL Analyzer Tool.
Performs strict static analysis on candidate URLs without opening or visiting the destination.
Evaluates structure, obfuscation, IP hosts, credential triggers, and domain deception.
"""

import re
from urllib.parse import urlparse, unquote


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "banking", "secure",
    "update", "auth", "account", "wallet", "confirm", "recovery",
    "password", "credential", "suspend", "unlock", "billing", "invoice"
]

SUSPICIOUS_PORTS = {8080, 8443, 8888, 8000, 1337, 3000, 4444, 5555, 9999}

POPULAR_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "bankofamerica", "chase", "wellsfargo"]


def analyze_url(url: str) -> dict:
    """
    Statically inspects a URL for deceptive and malicious patterns.
    
    Args:
        url: The candidate URL string to evaluate.
        
    Returns:
        Structured dictionary containing url, risk_score, risk_level, signals, and safe_to_visit flag.
    """
    if not url or not isinstance(url, str):
        return {
            "url": str(url),
            "risk_score": 0,
            "risk_level": "LOW",
            "signals": ["Invalid or empty URL string provided"],
            "safe_to_visit": False
        }

    url = url.strip()
    signals = []
    score = 0

    # Ensure URL has a scheme for parsing
    parseable_url = url
    if not re.match(r"^[a-zA-Z]+://", url):
        parseable_url = "http://" + url

    try:
        parsed = urlparse(parseable_url)
    except Exception as e:
        return {
            "url": url,
            "risk_score": 75,
            "risk_level": "HIGH",
            "signals": [f"Malformed URL structure could not be parsed: {e}"],
            "safe_to_visit": False
        }

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_lower = url.lower()

    # 1. Scheme Analysis: Plaintext HTTP vs HTTPS
    if parsed.scheme.lower() == "http":
        score += 20
        signals.append("Insecure HTTP transport (unencrypted communications)")
    elif parsed.scheme.lower() not in ("http", "https"):
        score += 35
        signals.append(f"Non-standard protocol scheme: '{parsed.scheme}'")

    # 2. IP Address Hostname Detection
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        score += 45
        signals.append(f"URL uses a raw IP address hostname ({hostname}) instead of a verified domain")

    # 3. Non-Standard / Suspicious Port Detection
    if parsed.port:
        if parsed.port in SUSPICIOUS_PORTS:
            score += 30
            signals.append(f"Suspicious high-risk port detected: :{parsed.port}")
        elif (parsed.scheme == "https" and parsed.port != 443) or (parsed.scheme == "http" and parsed.port != 80):
            score += 15
            signals.append(f"Non-standard web port: :{parsed.port}")

    # 4. Excessive Subdomains (Domain Obfuscation)
    domain_parts = hostname.split(".")
    if len(domain_parts) >= 5:
        score += 35
        signals.append(f"Excessive subdomain nesting ({len(domain_parts)} levels) used for obfuscation")
    elif len(domain_parts) == 4:
        score += 15
        signals.append("Elevated subdomain nesting (4 levels)")

    # 5. Length Analysis
    if len(url) > 100:
        score += 20
        signals.append(f"Unusually long URL length ({len(url)} characters), typical of token/credential obfuscation")
    elif len(url) > 75:
        score += 10
        signals.append(f"Moderately long URL ({len(url)} characters)")

    # 6. Suspicious Characters & Redirection Tricks
    if "@" in parseable_url.split("?")[0]:
        score += 50
        signals.append("Embedded '@' symbol detected before path (classic authentication redirection exploit)")

    if "//" in path:
        score += 20
        signals.append("Consecutive slashes ('//') in path indicating redirection evasion")

    # 7. Encoded Characters & Obfuscation
    decoded_url = unquote(url)
    if decoded_url != url:
        # Check for multiple/excessive percent encoding
        percent_count = url.count("%")
        if percent_count >= 3:
            score += 25
            signals.append(f"High frequency of percent-encoded characters ({percent_count} encoded sequences)")
        if "%2e%2e" in full_lower or "%2f" in full_lower:
            score += 30
            signals.append("Encoded directory traversal or path separators detected")

    # 8. Brand Impersonation Mismatch
    for brand in POPULAR_BRANDS:
        if brand in full_lower:
            # Check if brand is in subdomain or path, but NOT the registered root domain
            root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
            if brand not in root_domain:
                score += 45
                signals.append(f"Brand deception: '{brand}' referenced in URL path/subdomain while root domain is '{root_domain}'")
                break

    # 9. Credential Harvesting & High-Risk Trigger Keywords
    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
    if detected_keywords:
        score += min(30, len(detected_keywords) * 12)
        signals.append(f"Credential/authentication keywords detected in URL path: {', '.join(detected_keywords[:4])}")

    # 10. Normalize Score & Determine Risk Level
    risk_score = min(100, max(0, score))
    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 55:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not signals:
        signals.append("Standard URL structure with no obvious static threat indicators")

    safe_to_visit = (risk_score <= 25 and risk_level == "LOW")

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "safe_to_visit": safe_to_visit
    }
