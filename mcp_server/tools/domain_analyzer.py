"""
PhishGuard AI - MCP Domain Analyzer Tool.
Performs safe, local domain-level threat analysis without requiring external WHOIS network calls or paid API keys.
Evaluates syntax, suspicious TLDs, Punycode/IDN homographs, hyphen stuffing, and brand typo-squatting.
"""

import re


SUSPICIOUS_TLDS = {
    "xyz", "top", "ru", "cc", "tk", "zip", "mov", "click", "buzz",
    "fit", "work", "icu", "monster", "rest", "cam", "quest", "link",
    "gq", "cf", "ml", "ga", "sbs", "cfd", "live"
}

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "facebook", "instagram",
    "coinbase", "binance", "metamask", "whatsapp"
]


def analyze_domain(domain: str) -> dict:
    """
    Safely inspects a domain for high-risk naming patterns, suspicious TLDs,
    Punycode homoglyphs, and brand impersonation.
    
    Args:
        domain: Domain name string (e.g. 'paypal-security-alert.xyz' or 'github.com')
        
    Returns:
        Structured dictionary with domain, risk_level, signals, lookup_available status,
        and local_analysis breakdown.
    """
    if not domain or not isinstance(domain, str):
        return {
            "domain": str(domain),
            "risk_level": "LOW",
            "signals": ["Invalid or empty domain string provided"],
            "lookup_available": False,
            "reason": "Invalid domain input",
            "local_analysis": {"valid_syntax": False}
        }

    # Clean domain (strip whitespace, protocol prefix, and trailing path)
    cleaned = domain.strip().lower()
    cleaned = re.sub(r"^[a-zA-Z]+://", "", cleaned)
    cleaned = cleaned.split("/")[0].split(":")[0]

    signals = []
    score = 0

    # 1. IP Address Check
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    is_ip = bool(re.match(ip_pattern, cleaned))
    if is_ip:
        score += 50
        signals.append(f"Target is a raw IP address ({cleaned}), not a registered domain name")

    # 2. Syntax Validation
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    valid_syntax = bool(re.match(domain_regex, cleaned)) or is_ip
    if not valid_syntax and not cleaned.startswith("xn--"):
        score += 25
        signals.append("Non-standard domain syntax or invalid characters detected")

    # 3. Punycode / Internationalized Domain Name (IDN) Homograph Attack
    is_punycode = "xn--" in cleaned
    if is_punycode:
        score += 45
        signals.append(f"Punycode encoding detected ('{cleaned}'). Potential IDN homograph impersonation attack")

    # 4. TLD Analysis
    parts = cleaned.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        score += 35
        signals.append(f"High-abuse / suspicious TLD (.{tld}) commonly leveraged in disposable phishing campaigns")

    # 5. Excessive Subdomains
    subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
    if subdomain_count >= 3:
        score += 30
        signals.append(f"Excessive subdomain depth ({subdomain_count} subdomains) observed")

    # 6. Hyphen Stuffing (e.g. paypal-account-verify-support.com)
    hyphen_count = cleaned.count("-")
    if hyphen_count >= 3:
        score += 35
        signals.append(f"Excessive hyphen stuffing ({hyphen_count} hyphens) typical of brand spoofing")
    elif hyphen_count == 2:
        score += 15
        signals.append("Multiple hyphens detected in domain name")

    # 7. Brand Impersonation & Typosquatting in Domain
    base_name = parts[-2] if len(parts) >= 2 else cleaned
    for brand in KNOWN_BRANDS:
        if brand in cleaned:
            # If the brand is present, but the domain isn't the canonical domain
            if base_name != brand:
                score += 45
                signals.append(f"Brand deception: Contains '{brand}' within non-official domain '{cleaned}'")
                break

    # 8. Numeric entropy / character mixing
    digits_count = sum(c.isdigit() for c in base_name)
    if digits_count >= 4 and not is_ip:
        score += 20
        signals.append("High numeric entropy in domain label (random number strings)")

    # Compute risk level
    risk_score = min(100, max(0, score))
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 45:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not signals:
        signals.append("Standard domain syntax and recognized TLD structure")

    local_analysis = {
        "domain": cleaned,
        "valid_syntax": valid_syntax,
        "is_ip_address": is_ip,
        "is_punycode": is_punycode,
        "tld": tld,
        "subdomain_depth": subdomain_count,
        "hyphen_count": hyphen_count,
        "estimated_risk_score": risk_score
    }

    return {
        "domain": cleaned,
        "risk_level": risk_level,
        "signals": signals,
        "lookup_available": False,
        "reason": "External public WHOIS/RDAP lookup is disabled to prevent uncontrolled network calls; static syntax, homograph, and TLD reputation checks performed locally",
        "local_analysis": local_analysis
    }
