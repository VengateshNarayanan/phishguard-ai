"""
PhishGuard AI - Main FastAPI Application (Phase 2).
Exposes RESTful endpoints for phishing analysis and health status,
delegating threat assessment to the MCP-powered Security Agent.
"""

import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    McpStatusResponse,
)
from agent import analyze_with_agent, security_agent

app = FastAPI(
    title="PhishGuard AI",
    version="2.0.0",
    description="MCP-Powered AI Phishing, Scam, and Threat Intelligence System.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure Cross-Origin Resource Sharing (CORS) to allow browser clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits requests from local file:// and web servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Status"])
def root():
    """
    Root status endpoint providing basic API information and documentation links.
    """
    return {
        "name": "PhishGuard AI API",
        "version": "2.0.0",
        "phase": "Phase 2 (MCP-Powered)",
        "status": "online",
        "endpoints": {
            "health": "/health",
            "mcp_status": "/mcp/status",
            "analyze": "/analyze",
            "docs": "/docs",
            "dashboard": "/app/"
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["Status"])
def health_check():
    """
    Health check endpoint returning service operational status.
    """
    return HealthResponse(status="healthy")


@app.get("/mcp/status", response_model=McpStatusResponse, tags=["MCP"])
def mcp_status():
    """
    Returns the current operational readiness and registered tools of the MCP server.
    """
    server_ready = security_agent.server is not None
    return McpStatusResponse(
        status="connected" if server_ready else "offline",
        tools=["analyze_url", "analyze_domain", "analyze_email_headers"],
        server_name="phishguard-security-tools"
    )


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_email_or_message(request: AnalyzeRequest):
    """
    Analyze an email or message for phishing, scam, or social engineering indicators.
    Coordinates Gemini reasoning with MCP tools (URL, domain, header analyzers).
    """
    # Guard against completely empty or whitespace-only messages
    if not request.message or not request.message.strip():
        raise HTTPException(
            status_code=422,
            detail="The 'message' field cannot be empty or contain only whitespace."
        )

    # Delegate analysis to MCP-powered Security Agent
    try:
        return await analyze_with_agent(request)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent analysis failed: {str(e)}")


# Convenience: Mount frontend directory if it exists relative to the backend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
