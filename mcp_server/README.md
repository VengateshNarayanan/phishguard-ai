# PhishGuard AI — MCP Security Server

This directory contains the independent **Model Context Protocol (MCP)** server for PhishGuard AI.
It exposes specialized security tools that allow the PhishGuard Security Agent to gather empirical evidence before finalizing threat assessments.

---

## Architecture

```
mcp_server/
├── server.py                        # MCP Server implementation using official Python MCP SDK
├── tools/
│   ├── url_analyzer.py              # Static URL threat inspector (No network fetching)
│   ├── domain_analyzer.py           # Domain syntax, TLD risk, and homograph inspector
│   └── email_header_analyzer.py     # RFC 822 email header authentication parser
└── README.md                        # Documentation
```

---

## Exposed MCP Tools

### 1. `analyze_url(url: str) -> dict`
Statically inspects a candidate URL without following redirects, visiting the host, or executing code.
- **Evaluates**: HTTP vs HTTPS, raw IPv4/IPv6 hosts, non-standard ports (`:8080`, `:1337`), excessive subdomain nesting, length > 100 chars, `@` redirection tricks, percent-encoding abuse, brand deception in paths, and credential harvesting keywords.
- **Returns**: Risk score (0–100), risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), signals list, and `safe_to_visit` boolean.

### 2. `analyze_domain(domain: str) -> dict`
Analyzes domain structure, TLD reputation, and impersonation signals safely without uncontrolled network lookups.
- **Evaluates**: Syntax validity, IP-based targets, suspicious TLDs (`.xyz`, `.top`, `.ru`, `.click`, `.zip`), Punycode IDN homoglyphs (`xn--`), hyphen stuffing, and brand typosquatting.
- **Returns**: Domain risk level, signals list, and local analysis breakdown. Clearly identifies external WHOIS lookup availability status.

### 3. `analyze_email_headers(headers: str) -> dict`
Parses raw multiline email headers or structured key-value headers.
- **Evaluates**: `From` vs `Reply-To` mismatch, `Return-Path` inconsistency, SPF status (`pass`, `fail`, `softfail`), DKIM signature verification, DMARC alignment, and suspicious relay hops.
- **Returns**: Extracted addresses, mismatch flag, SPF/DKIM/DMARC status, signals list, and overall risk rating.

---

## Running the Server Standalone

The server can be launched directly using the Python MCP runner:

```powershell
# From the phishguard-ai root directory:
.\backend\venv\Scripts\python.exe mcp_server/server.py
```

The server listens on `stdio` by default and is fully compliant with MCP clients (such as Claude Desktop, Antigravity, or PhishGuard Agent).
