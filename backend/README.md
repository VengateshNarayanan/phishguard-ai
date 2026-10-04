# 🛡️ PhishGuard AI

> **AI-powered phishing, scam, and social-engineering detection system built with FastAPI, Google Gemini, and MCP security tools.**

## 🌐 Live Demo

### 🚀 [Open PhishGuard AI](https://phishguard-ai-xm8d.onrender.com/app/)



> The application is deployed on Render and can be tested directly through the live dashboard.

---

## 📌 Overview

PhishGuard AI is an AI-assisted cybersecurity application that analyzes emails and messages for **phishing, scams, and social-engineering attacks**.

The system combines **Google Gemini** for intelligent threat assessment with **MCP-based security tools** that investigate suspicious URLs, domains, and email headers.

Instead of relying only on a single AI response, the system can collect additional security evidence and present an explainable risk assessment.

---

## 🚀 Key Features

### 🤖 AI Threat Analysis

* Google Gemini-powered message analysis
* Risk score from **0–100**
* Threat classification:

  * `SAFE`
  * `SUSPICIOUS`
  * `PHISHING`
  * `SCAM`
* Severity levels:

  * `LOW`
  * `MEDIUM`
  * `HIGH`
  * `CRITICAL`
* AI-generated security summary
* Threat indicators
* Detailed reasoning
* Recommended security action

### 🔎 MCP Security Investigation

PhishGuard AI includes specialized security tools for additional investigation.

#### 🔗 URL Analyzer

Detects:

* HTTP vs HTTPS
* IP-based URLs
* Suspicious ports
* Excessive subdomains
* Suspicious URL length
* `@` redirection patterns
* Percent-encoding abuse
* Phishing-related keywords
* Suspicious URL structures

#### 🌐 Domain Analyzer

Analyzes:

* Suspicious TLDs
* IP-based domains
* Excessive domain depth
* Punycode indicators
* Potential typo-squatting
* Suspicious domain structures
* Hyphen-based impersonation patterns

#### 📧 Email Header Analyzer

Checks:

* `From` vs `Reply-To` mismatch
* SPF results
* DKIM results
* DMARC results
* Return-Path discrepancies
* Suspicious relay information

---

## 🧠 Agentic Security Analysis

The Security Agent determines which security tools are relevant to the submitted message.

For example:

```text
Message
   │
   ▼
Security Agent
   │
   ├── No URL → Skip URL analysis
   │
   ├── Suspicious URL → Analyze URL
   │
   ├── Suspicious domain → Analyze domain
   │
   └── Email headers → Analyze headers
             │
             ▼
       Security Evidence
             │
             ▼
        Gemini Analysis
             │
             ▼
      Final Risk Assessment
```

This avoids unnecessary tool execution and provides additional evidence for the final assessment.

---

## 🏗️ System Architecture

```text
                         USER
                           │
                           ▼
                 ┌──────────────────┐
                 │   Web Dashboard   │
                 │ HTML/CSS/JS       │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     FastAPI      │
                 │     Backend      │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  Security Agent  │
                 └────────┬─────────┘
                          │
                 ┌────────┴────────┐
                 │                 │
                 ▼                 ▼
          Gemini Analysis     MCP Security Tools
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
               URL Analyzer  Domain Analyzer  Header Analyzer
                    │             │             │
                    └─────────────┼─────────────┘
                                  │
                                  ▼
                         Security Evidence
                                  │
                                  ▼
                         Final AI Assessment
```

---

## 🛠️ Technology Stack

| Component     | Technology                   |
| ------------- | ---------------------------- |
| Frontend      | HTML5, CSS3, JavaScript      |
| Backend       | Python, FastAPI              |
| Validation    | Pydantic                     |
| AI Model      | Google Gemini                |
| AI SDK        | `google-genai`               |
| Agent         | Python Security Agent        |
| Tool Protocol | Model Context Protocol (MCP) |
| MCP SDK       | Python MCP SDK               |
| Testing       | Pytest                       |
| Server        | Uvicorn                      |
| Deployment    | Render                       |
| Repository    | GitHub                       |

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

## ⚙️ Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/VengateshNarayanan/phishguard-ai.git
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
GEMINI_MODEL=gemini-3.8-flash
DEMO_MODE=false
```

For local testing without Gemini:

```env
DEMO_MODE=true
```

**Never commit your `.env` file to GitHub.**

---

## ▶️ Run Locally

Start the FastAPI backend:

```powershell
cd backend
uvicorn main:app --reload
```

Open:

```text
http://127.0.0.1:8000/app/
```

Swagger documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 🔌 API Endpoints

### `GET /`

Returns API information and project metadata.

### `GET /health`

Checks backend health.

### `GET /mcp/status`

Returns MCP security-tool status.

### `POST /analyze`

Analyzes an email or message.

Example:

```json
{
  "sender": "security-alert@instagram-verification.com",
  "subject": "URGENT: Your Instagram Account Will Be Permanently Disabled",
  "message": "We detected unusual activity on your Instagram account..."
}
```

---

## 🧪 Example Threat

**Sender**

```text
security-alert@instagram-verification.com
```

**Subject**

```text
URGENT: Your Instagram Account Will Be Permanently Disabled
```

The system should identify indicators such as:

```text
• Urgency and time pressure
• Brand impersonation
• Account suspension threat
• Suspicious verification URL
• Social engineering
• Potential credential harvesting
```

Expected classification:

```text
PHISHING
```

---

## 🧪 Testing

Run the automated test suite:

```powershell
cd backend
pytest test_api.py -v
```

Tests cover:

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
* Security Agent behavior
* Error handling
* Phase 1 regression tests

---

## 🔐 Security Considerations

PhishGuard AI follows defensive security principles:

* API keys are stored using environment variables.
* `.env` is excluded from Git.
* User-provided content is treated as untrusted.
* Submitted URLs are analyzed syntactically and are not automatically opened.
* External URLs are not automatically executed.
* Frontend output is sanitized.
* Missing security information is not fabricated.
* The system does not automatically send messages, delete emails, or take destructive actions.

---

## 📊 Development Progress

### Phase 1 — Core AI Analyzer ✅

* FastAPI backend
* Gemini integration
* Pydantic validation
* AI threat classification
* Risk scoring
* Security dashboard
* Automated testing

### Phase 2 — MCP Security Agent ✅

* Security Agent
* MCP security tools
* URL investigation
* Domain investigation
* Email-header analysis
* Tool evidence
* Investigation steps
* MCP status monitoring
* Intelligent tool selection
* Graceful fallback handling

### Phase 3 — Future Possibilities 🔮

Potential extensions:

* Gmail / Outlook integration
* Real-time mailbox monitoring
* External URL reputation services
* WHOIS/domain intelligence
* Real SPF/DKIM/DMARC validation
* Threat-intelligence APIs
* Human-approved incident reporting
* Automated security workflows

---

## ⚠️ Disclaimer

PhishGuard AI is designed for **educational, research, and defensive cybersecurity purposes**.

AI-generated security assessments may contain errors. Important security decisions should be independently verified.

---

## 👨‍💻 Author

**Vengatesh Narayanan**

B.Tech — Computer Science Engineering (IoT & Cybersecurity)

### Areas of Interest

* Artificial Intelligence
* AI Agents
* Model Context Protocol (MCP)
* Cybersecurity
* Backend Development
* Software Engineering

---

⭐ If you find PhishGuard AI useful or interesting, consider starring the repository.
