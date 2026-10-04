"""
PhishGuard AI - Standalone MCP Threat Intelligence Server.
Exposes security tools through the official Model Context Protocol (MCP) Python SDK.
Tools exposed:
- analyze_url(url: str)
- analyze_domain(domain: str)
- analyze_email_headers(headers: str)
"""

import sys
import os

# Ensure tools directory is discoverable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.url_analyzer import analyze_url as run_analyze_url
from tools.domain_analyzer import analyze_domain as run_analyze_domain
from tools.email_header_analyzer import analyze_email_headers as run_analyze_email_headers

# Import official MCP server
try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    # Fallback for mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

# Initialize MCP server
server = MCPServer(
    name="phishguard-security-tools",
    instructions=(
        "PhishGuard AI Threat Intelligence Server providing static security tools: "
        "URL static inspection, domain reputation & homograph analysis, and RFC 822 email header validation."
    )
)


@server.tool(name="analyze_url", description="Statically inspects a URL for deceptive patterns, IP hostnames, high-risk ports, and credential harvesting signals without visiting the destination.")
def analyze_url(url: str) -> dict:
    """
    Analyzes a URL for phishing and security risks.
    """
    return run_analyze_url(url)


@server.tool(name="analyze_domain", description="Analyzes domain syntax, suspicious TLDs, Punycode/IDN homograph attacks, hyphen stuffing, and brand typo-squatting safely.")
def analyze_domain(domain: str) -> dict:
    """
    Analyzes a domain for spoofing and reputation indicators.
    """
    return run_analyze_domain(domain)


@server.tool(name="analyze_email_headers", description="Parses and analyzes RFC 822 email headers for From vs Reply-To mismatches, SPF, DKIM, and DMARC authentication failures.")
def analyze_email_headers(headers: str) -> dict:
    """
    Analyzes email headers for authentication and sender consistency.
    """
    return run_analyze_email_headers(headers)


def main():
    """Runs the MCP server over standard input/output transport."""
    print("Starting PhishGuard MCP Server...", file=sys.stderr)
    server.run()


if __name__ == "__main__":
    main()
