# PhishGuard AI - Backend Service

FastAPI-powered REST backend for PhishGuard AI, leveraging the modern `google-genai` Python SDK to analyze digital communications for phishing attacks, scams, and social engineering indicators.

---

## Architecture Overview

```
backend/
├── main.py            # FastAPI application routes, CORS middleware, and static mount
├── models.py          # Pydantic schemas for request/response validation & typing
├── ai_service.py      # Google GenAI integration, cybersecurity prompts & fallback analyzer
├── test_api.py        # Automated test suite using pytest and FastAPI TestClient
├── requirements.txt   # Python dependency specifications
├── .env.example       # Template for environment configuration
└── README.md          # Backend documentation
```

---

## Prerequisites

- **Python 3.10+** (Tested on Python 3.13)
- **Google Gemini API Key** (Free tier available at [Google AI Studio](https://aistudio.google.com/))

---

## Quickstart Setup

### 1. Create a Virtual Environment

On Windows PowerShell:
```powershell
# From the phishguard-ai/backend directory:
py -m venv venv
```

Activate the virtual environment:
```powershell
.\venv\Scripts\Activate.ps1
```
*(If you encounter execution policy restrictions on PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### 2. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the template:
```powershell
copy .env.example .env
```

Edit `.env` and set your Gemini API key:
```ini
GEMINI_API_KEY=your_actual_api_key_from_google_ai_studio
GEMINI_MODEL=gemini-2.5-flash
DEMO_MODE=false
```

> **Note**: If you don't have a Gemini API key yet, you can set `DEMO_MODE=true` to test the application using the built-in heuristic cybersecurity analyzer.

### 4. Run the Development Server

```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The API will be available at:
- **API Root**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## API Endpoints

### 1. `GET /`
Returns the status and links to documentation.

**Response**:
```json
{
  "name": "PhishGuard AI API",
  "version": "1.0.0",
  "status": "online",
  "endpoints": {
    "health": "/health",
    "analyze": "/analyze",
    "docs": "/docs",
    "dashboard": "/app/"
  }
}
```

### 2. `GET /health`
Liveness probe.

**Response**:
```json
{
  "status": "healthy"
}
```

### 3. `POST /analyze`
Analyzes an email or message.

**Request Payload**:
```json
{
  "sender": "security-alert@paypal-update.com",
  "subject": "URGENT: Your account has been suspended!",
  "message": "We noticed suspicious activity. Click here to confirm your credentials: http://fake-login.ru"
}
```

**Response Payload**:
```json
{
  "risk_score": 92,
  "classification": "PHISHING",
  "severity": "CRITICAL",
  "summary": "High-confidence phishing attempt impersonating PayPal with credential harvesting link.",
  "reasons": [
    "Artificial urgency used to induce panic and bypass critical thinking",
    "Suspicious external domain mismatched with official PayPal branding",
    "Request for credential entry on an unverified third-party page"
  ],
  "indicators": [
    "Urgency / Fear manipulation",
    "Credential harvesting link",
    "Brand impersonation (PayPal)",
    "Unusual sender domain"
  ],
  "recommended_action": "Do not click any links or provide credentials. Flag as phishing and report to IT Security."
}
```

---

## Running Automated Tests

Run the test suite with `pytest`:
```powershell
pytest test_api.py -v
```
