# 🛡️ PhishGuard AI

**AI-powered phishing, scam, and social-engineering detection system built with FastAPI, Gemini, and MCP security tools.**

PhishGuard AI analyzes emails and messages to identify potential phishing and scam threats. It combines AI-based security analysis with specialized MCP tools for URL, domain, and email-header investigation.

> ⚠️ **Note:** PhishGuard AI is an AI-assisted security analysis tool and does not guarantee detection of every malicious message.

---

## 🚀 Features

### 🤖 AI-Powered Threat Analysis

* Analyzes emails and messages using Google Gemini.
* Generates a **0–100 risk score**.
* Classifies threats as:

  * `SAFE`
  * `SUSPICIOUS`
  * `PHISHING`
  * `SCAM`
* Assigns severity levels from `LOW` to `CRITICAL`.
* Provides security reasoning, detected indicators, and recommended actions.

### 🔎 MCP Security Investigation

PhishGuard AI uses MCP-based security tools to investigate suspicious content:

* **URL Analyzer**

  * Detects suspicious URL structures
  * Checks HTTPS usage
  * Identifies IP-based URLs
  * Detects suspicious ports and URL patterns
  * Identifies phishing-related keywords

* **Domain Analyzer**

  * Detects suspicious domains
  * Identifies suspicious TLDs
  * Detects punycode indicators
  * Identifies potential typo-squatting patterns
  * Analyzes suspicious domain structures

* **Email Header Analyzer**

  * Checks `From` vs `Reply-To`
  * Analyzes SPF results
  * Analyzes DKIM results
  * Analyzes DMARC results
  * Identifies suspicious mail-routing indicators

### 🧠 Agentic Analysis

The security agent intelligently determines which investigation tools are relevant instead of executing every tool for every message.

### 🖥️ Cybersecurity Dashboard

* Responsive dark-themed interface
* Risk score visualization
* Threat classification
* Severity indicators
* Security investigation timeline
* Tool evidence display
* Recommended security actions

### 🧪 Testing

* Automated FastAPI tests using Pytest
* Safe, suspicious, phishing, and scam test scenarios
* MCP tool testing
* Error and fallback handling

---

## 🏗️ Architecture

```text
                    ┌─────────────────────┐
                    │   User / Email      │
                    │      Message        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Frontend       │
                    │ HTML / CSS / JS     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      FastAPI        │
                    │       Backend       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Security Agent    │
                    │      + Gemini       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    MCP Security     │
                    │       Tools         │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
      URL Analyzer      Domain Analyzer    Email Header
                                            Analyzer
             │                 │                 │
             └─────────────────┼─────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Security Evidence  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Final AI Risk     │
                    │    Assessment       │
                    └─────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer         | Technology              |
| ------------- | ----------------------- |
| Frontend      | HTML5, CSS3, JavaScript |
| Backend       | Python, FastAPI         |
| Validation    | Pydantic                |
| AI            | Google Gemini           |
| AI SDK        | `google-genai`          |
| Agent Layer   | Python                  |
| Tool Protocol | MCP                     |
| MCP SDK       | Python MCP SDK          |
| Testing       | Pytest                  |
| Server        | Uvicorn                 |

---

## 📁 Project Structure

```text
phishguard-ai/
│
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── ai_service.py
│   ├── agent.py
│   ├── test_api.py
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── mcp_server/
│   ├── server.py
│   ├── tools/
│   │   ├── url_analyzer.py
│   │   ├── domain_analyzer.py
│   │   └── email_header_analyzer.py
│   └── README.md
│
├── test_examples.json
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
cd phishguard-ai
```

### 2. Create a virtual environment

Windows:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

Create:

```text
backend/.env
```

Add:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
DEMO_MODE=false
```

For local testing without an API key:

```env
DEMO_MODE=true
```

Never commit your `.env` file.

---

## ▶️ Running the Application

### Start the FastAPI backend

```powershell
cd backend
uvicorn main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger API documentation:

```text
http://127.0.0.1:8000/docs
```

Dashboard:

```text
http://127.0.0.1:8000/app/
```

### MCP Server

The MCP security server can be started independently according to the instructions in:

```text
mcp_server/README.md
```

---

## 🔌 API

### `GET /`

Returns basic API information.

### `GET /health`

Checks backend availability.

### `GET /mcp/status`

Returns the current MCP tool status.

### `POST /analyze`

Analyzes an email or message.

Example request:

```json
{
  "sender": "security-alert@example.com",
  "subject": "Urgent Account Verification",
  "message": "Your account will be suspended. Verify your identity immediately."
}
```

Example response:

```json
{
  "risk_score": 94,
  "classification": "PHISHING",
  "severity": "CRITICAL",
  "summary": "The message contains multiple phishing indicators.",
  "reasons": [
    "Urgency-based manipulation",
    "Account suspension threat",
    "Suspicious verification request"
  ],
  "indicators": [
    "Social engineering",
    "Credential harvesting"
  ],
  "recommended_action": "Do not click links or provide credentials.",
  "tool_evidence": [],
  "analysis_steps": [
    "Initial message analysis completed",
    "Threat indicators identified",
    "Final risk assessment completed"
  ]
}
```

---

## 🧪 Testing

Run the automated tests:

```powershell
cd backend
pytest test_api.py -v
```

The test suite covers:

* API health
* Input validation
* Safe messages
* Suspicious messages
* Phishing messages
* Scam messages
* URL analysis
* Domain analysis
* Email-header analysis
* MCP functionality
* Agent behavior
* Error handling

---

## 🔐 Security Considerations

PhishGuard AI follows several security principles:

* API keys are stored in environment variables.
* `.env` is excluded from Git.
* User-provided content is treated as untrusted.
* Submitted URLs are not automatically opened.
* No arbitrary files are downloaded from submitted URLs.
* Frontend output is sanitized.
* External threat intelligence is not fabricated.
* The system does not automatically delete, report, or respond to emails.

---

## 📊 Current Development Status

### Phase 1 — Core AI Analyzer ✅

* FastAPI backend
* Gemini integration
* Pydantic validation
* Risk scoring
* Threat classification
* Cybersecurity dashboard
* Automated testing

### Phase 2 — MCP Security Agent ✅

* Security agent
* MCP security tools
* URL analysis
* Domain analysis
* Email-header analysis
* Tool evidence
* Investigation steps
* MCP status monitoring
* Agentic tool selection

### Phase 3 — Future Improvements 🔮

Potential future extensions include:

* Gmail / Outlook integration
* Real-time mailbox monitoring
* External URL reputation services
* WHOIS/domain intelligence
* Real SPF/DKIM/DMARC validation
* Human-approved incident reporting
* Automated security workflows
* Threat-intelligence APIs

---

## ⚠️ Disclaimer

PhishGuard AI is intended for **educational, research, and defensive cybersecurity purposes**.

AI-generated security assessments may contain errors. Users should independently verify important security decisions before taking action.

---

## 👨‍💻 Author

**Vengatesh Narayanan**

B.Tech — Computer Science Engineering (IoT & Cybersecurity)

Interested in:

* Artificial Intelligence
* AI Agents
* MCP
* Cybersecurity
* Backend Development
* Software Engineering

---

⭐ If you find this project interesting, consider giving the repository a star.
