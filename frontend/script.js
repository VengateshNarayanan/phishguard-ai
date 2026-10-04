/**
 * PhishGuard AI - Frontend Controller (Phase 2 MCP Enhanced)
 * Handles user interactions, preset loading, API calls, and threat result rendering,
 * including Model Context Protocol (MCP) tool evidence and investigation steps.
 */

// Determine the API base URL. If hosted by FastAPI under /app, use origin; otherwise default to local FastAPI port 8000.
const API_BASE_URL = window.location.origin.includes(":8000") 
  ? window.location.origin 
  : "http://127.0.0.1:8000";

// Preset test scenarios for fast, 1-click evaluation
const PRESETS = {
  safe: {
    sender: "sarah.jenkins@acme-corp.internal",
    subject: "Quarterly Planning Deck Review & Sync",
    message: "Hi team,\n\nPlease find time to review the Q3 strategic roadmap slides before our all-hands sync this Thursday at 2:00 PM. Feel free to leave comments directly on our internal knowledge base.\n\nBest regards,\nSarah Jenkins\nDirector of Operations"
  },
  suspicious: {
    sender: "dispatch-notice@global-express-delivery.net",
    subject: "Action Required: Undelivered Package #US-99210",
    message: "Your delivery could not be completed today due to an incomplete delivery address on file.\n\nPlease confirm your address and update your delivery preferences within 48 hours to avoid return to sender: https://global-express-dispatch-review.net/track?id=99210\n\nThank you,\nCustomer Dispatch Support"
  },
  phishing: {
    sender: "security-alert@paypal-account-security-center.com",
    subject: "URGENT: Unauthorized Login Detected - Account Suspended",
    message: "Dear Customer,\n\nWe detected suspicious login attempts on your PayPal account from an unrecognized IP address in Moscow, Russia. For your protection, your account has been temporarily locked.\n\nClick here immediately to verify your identity and restore access: http://192.168.1.150:8080/paypal-security/login\n\nIf you do not verify your credentials within 24 hours, your account and linked funds will be permanently disabled."
  },
  scam: {
    sender: "barrister.kofi@international-trust-fund.org",
    subject: "OFFICIAL NOTICE: Unclaimed Award of $4,500,000 USD",
    message: "Attention Beneficiary,\n\nI am Barrister Kofi Mensah, legal representative for an unclaimed inheritance fund amounting to $4,500,000 USD. You have been selected as the sole authorized recipient.\n\nTo initiate the release of these funds, kindly remit an administrative fee of $450 USD via Bitcoin or Western Union transfer to cover bank notarization.\n\nSend your full name, passport copy, and transaction receipt to begin."
  },
  headers: {
    sender: "PayPal Security <alert@paypal-account-center.com>",
    subject: "Immediate Action: Account Security Flag #8841",
    message: "From: PayPal Security <alert@paypal-account-center.com>\nReply-To: attacker@unverified-inbox.ru\nReturn-Path: <bounce@unverified-inbox.ru>\nAuthentication-Results: mx.google.com; spf=fail smtp.mailfrom=paypal-account-center.com; dkim=fail; dmarc=fail action=quarantine\nReceived: from untrusted-relay.ru (untrusted-relay.ru [185.220.101.5])\n\nDear Customer,\n\nYour account has been flagged for immediate identity re-verification. Reply immediately with your account PIN to restore access."
  }
};

// DOM Elements
const apiStatusBadge = document.getElementById("api-status-badge");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");

const mcpStatusBadge = document.getElementById("mcp-status-badge");
const mcpStatusDot = document.getElementById("mcp-status-dot");
const mcpStatusText = document.getElementById("mcp-status-text");

const alertBanner = document.getElementById("alert-banner");
const alertIcon = document.getElementById("alert-icon");
const alertMessage = document.getElementById("alert-message");
const alertCloseBtn = document.getElementById("alert-close-btn");

const senderInput = document.getElementById("sender-input");
const subjectInput = document.getElementById("subject-input");
const messageInput = document.getElementById("message-input");
const charCounter = document.getElementById("char-counter");
const clearBtn = document.getElementById("clear-btn");

const analyzeForm = document.getElementById("analyze-form");
const submitBtn = document.getElementById("submit-btn");
const submitSpinner = document.getElementById("submit-spinner");
const submitIcon = document.getElementById("submit-icon");
const submitLabel = document.getElementById("submit-label");

const resultsIdle = document.getElementById("results-idle");
const resultsContent = document.getElementById("results-content");
const resultScore = document.getElementById("result-score");
const scoreCircle = document.getElementById("score-circle");
const resultClassification = document.getElementById("result-classification");
const resultSeverity = document.getElementById("result-severity");
const resultSummary = document.getElementById("result-summary");
const resultIndicators = document.getElementById("result-indicators");
const resultReasons = document.getElementById("result-reasons");
const resultAction = document.getElementById("result-action");

const investigationStepsList = document.getElementById("investigation-steps-list");
const toolEvidenceGrid = document.getElementById("tool-evidence-grid");

/**
 * Escapes untrusted text to prevent XSS.
 */
function escapeHTML(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Displays an alert notification banner.
 */
function showAlert(message, type = "error") {
  alertMessage.textContent = message;
  alertBanner.className = `alert-banner ${type}`;
  alertIcon.textContent = type === "error" ? "⚠️" : "ℹ️";
  alertBanner.classList.remove("hidden");
}

/**
 * Hides the alert banner.
 */
function hideAlert() {
  alertBanner.classList.add("hidden");
}

/**
 * Updates the backend and MCP health status badges.
 */
async function checkSystemHealth() {
  // 1. Check FastAPI Backend Health
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(`${API_BASE_URL}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (response.ok) {
      statusDot.className = "status-dot online";
      statusText.textContent = "API: Online";
    } else {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (err) {
    statusDot.className = "status-dot offline";
    statusText.textContent = "API: Offline";
    showAlert(
      `Cannot connect to backend at ${API_BASE_URL}. Ensure uvicorn is running: uvicorn main:app --reload`,
      "error"
    );
  }

  // 2. Check MCP Server Readiness
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(`${API_BASE_URL}/mcp/status`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      mcpStatusDot.className = "status-dot online";
      mcpStatusText.textContent = "MCP: Connected (3 Tools)";
    } else {
      mcpStatusDot.className = "status-dot offline";
      mcpStatusText.textContent = "MCP: Unavailable";
    }
  } catch (err) {
    mcpStatusDot.className = "status-dot offline";
    mcpStatusText.textContent = "MCP: Offline";
  }
}

/**
 * Updates textarea character counter.
 */
function updateCharCount() {
  const count = messageInput.value.length;
  charCounter.textContent = `${count.toLocaleString()} character${count === 1 ? '' : 's'}`;
}

/**
 * Loads a selected preset example into the form.
 */
function loadPreset(key) {
  const preset = PRESETS[key];
  if (!preset) return;

  senderInput.value = preset.sender;
  subjectInput.value = preset.subject;
  messageInput.value = preset.message;
  updateCharCount();
  hideAlert();
}

/**
 * Clears the input form and resets results state.
 */
function resetForm() {
  senderInput.value = "";
  subjectInput.value = "";
  messageInput.value = "";
  updateCharCount();
  hideAlert();
  resultsContent.classList.add("hidden");
  resultsIdle.classList.remove("hidden");
}

/**
 * Renders structured tool evidence into cards.
 */
function renderToolEvidence(toolEvidence) {
  toolEvidenceGrid.innerHTML = "";

  if (!toolEvidence || toolEvidence.length === 0) {
    const emptyNotice = document.createElement("div");
    emptyNotice.className = "tool-card";
    emptyNotice.innerHTML = `
      <div class="tool-card-header">
        <span class="tool-name-badge">No External Tools Required</span>
        <span class="tool-risk-tag low">CLEAN</span>
      </div>
      <p style="font-size: 0.8rem; color: #9ca3af;">
        The Security Agent determined that no candidate URLs, unverified external domains, or RFC 822 email headers required tool investigation.
      </p>
    `;
    toolEvidenceGrid.appendChild(emptyNotice);
    return;
  }

  toolEvidence.forEach(item => {
    const card = document.createElement("div");
    card.className = "tool-card";

    const toolName = item.tool || "unknown_tool";
    const result = item.result || {};
    const riskLevel = (result.risk_level || item.status || "INFO").toLowerCase();

    let toolDisplayName = "MCP Tool";
    if (toolName === "analyze_url") toolDisplayName = "✓ URL Static Analyzer";
    else if (toolName === "analyze_domain") toolDisplayName = "✓ Domain Reputation Analyzer";
    else if (toolName === "analyze_email_headers") toolDisplayName = "✓ Email Header Spoofing Inspector";

    let targetHTML = "";
    if (item.target) {
      targetHTML = `<div class="tool-target-text">Target: ${escapeHTML(item.target)}</div>`;
    }

    let signalsHTML = "";
    const signals = result.signals || [];
    if (signals.length > 0) {
      signalsHTML = `<ul class="tool-signals-list">${signals.map(s => `<li>${escapeHTML(s)}</li>`).join("")}</ul>`;
    } else if (item.status === "unavailable") {
      signalsHTML = `<ul class="tool-signals-list"><li style="color: #fca5a5;">Tool execution was unavailable: ${escapeHTML(item.error || 'Timeout')}</li></ul>`;
    }

    card.innerHTML = `
      <div class="tool-card-header">
        <span class="tool-name-badge">${escapeHTML(toolDisplayName)}</span>
        <span class="tool-risk-tag ${riskLevel}">${escapeHTML(riskLevel.toUpperCase())}</span>
      </div>
      ${targetHTML}
      ${signalsHTML}
    `;

    toolEvidenceGrid.appendChild(card);
  });
}

/**
 * Renders high-level agent investigation timeline steps.
 */
function renderInvestigationSteps(steps) {
  investigationStepsList.innerHTML = "";
  if (!steps || steps.length === 0) {
    const li = document.createElement("li");
    li.textContent = "Direct threat triage completed";
    investigationStepsList.appendChild(li);
    return;
  }

  steps.forEach(step => {
    const li = document.createElement("li");
    li.textContent = step;
    investigationStepsList.appendChild(li);
  });
}

/**
 * Updates the visual styling of the results display based on classification and score.
 */
function renderResults(data) {
  // Update Score
  const score = data.risk_score;
  resultScore.textContent = score;

  // Determine score color
  let scoreColor = "#10b981"; // Safe
  if (score > 85) {
    scoreColor = "#e11d48"; // Scam / Critical
  } else if (score > 55) {
    scoreColor = "#ef4444"; // Phishing
  } else if (score > 25) {
    scoreColor = "#f59e0b"; // Suspicious
  }
  scoreCircle.style.borderColor = scoreColor;

  // Update Classification Badge
  const classification = data.classification.toUpperCase();
  resultClassification.textContent = classification;
  resultClassification.className = "classification-badge";

  switch (classification) {
    case "SAFE":
      resultClassification.classList.add("state-safe");
      break;
    case "SUSPICIOUS":
      resultClassification.classList.add("state-suspicious");
      break;
    case "PHISHING":
      resultClassification.classList.add("state-phishing");
      break;
    case "SCAM":
      resultClassification.classList.add("state-scam");
      break;
    default:
      resultClassification.classList.add("state-suspicious");
  }

  // Update Severity Pill
  const severity = data.severity.toUpperCase();
  resultSeverity.textContent = severity;
  resultSeverity.className = "severity-pill";
  switch (severity) {
    case "LOW":
      resultSeverity.classList.add("severity-low");
      break;
    case "MEDIUM":
      resultSeverity.classList.add("severity-medium");
      break;
    case "HIGH":
      resultSeverity.classList.add("severity-high");
      break;
    case "CRITICAL":
      resultSeverity.classList.add("severity-critical");
      break;
  }

  // Update Summary
  resultSummary.textContent = data.summary;

  // Phase 2: Render Investigation Steps and Tool Evidence
  renderInvestigationSteps(data.analysis_steps);
  renderToolEvidence(data.tool_evidence);

  // Update Indicators
  resultIndicators.innerHTML = "";
  if (data.indicators && data.indicators.length > 0) {
    data.indicators.forEach(indicator => {
      const tag = document.createElement("span");
      tag.className = "indicator-tag";
      tag.textContent = indicator;
      resultIndicators.appendChild(tag);
    });
  } else {
    const tag = document.createElement("span");
    tag.className = "indicator-tag";
    tag.textContent = "None Detected";
    resultIndicators.appendChild(tag);
  }

  // Update Reasons
  resultReasons.innerHTML = "";
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach(reason => {
      const li = document.createElement("li");
      li.textContent = reason;
      resultReasons.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "No specific anomaly detected.";
    resultReasons.appendChild(li);
  }

  // Update Recommended Action
  resultAction.textContent = data.recommended_action;

  // Switch views
  resultsIdle.classList.add("hidden");
  resultsContent.classList.remove("hidden");
}

/**
 * Handles form submission to the FastAPI backend.
 */
async function handleSubmit(event) {
  event.preventDefault();
  hideAlert();

  const message = messageInput.value.trim();
  if (!message) {
    showAlert("Please enter or paste the message content or email headers to analyze.", "error");
    messageInput.focus();
    return;
  }

  const payload = {
    sender: senderInput.value.trim(),
    subject: subjectInput.value.trim(),
    message: message
  };

  // Set loading state
  submitBtn.disabled = true;
  submitSpinner.classList.remove("hidden");
  submitIcon.classList.add("hidden");
  submitLabel.textContent = "Agent Investigating with MCP Tools...";

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const responseData = await response.json().catch(() => null);

    if (!response.ok) {
      const errorMsg = responseData && responseData.detail
        ? (typeof responseData.detail === "string" ? responseData.detail : JSON.stringify(responseData.detail))
        : `Request failed with status ${response.status}`;
      throw new Error(errorMsg);
    }

    if (!responseData) {
      throw new Error("Received empty response from server.");
    }

    renderResults(responseData);

  } catch (error) {
    console.error("Analysis Error:", error);
    showAlert(`Analysis failed: ${error.message}`, "error");
  } finally {
    submitBtn.disabled = false;
    submitSpinner.classList.add("hidden");
    submitIcon.classList.remove("hidden");
    submitLabel.textContent = "Analyze with Security Agent";
  }
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  // Check backend & MCP health
  checkSystemHealth();

  // Character counter
  messageInput.addEventListener("input", updateCharCount);

  // Clear button
  clearBtn.addEventListener("click", resetForm);

  // Alert close button
  alertCloseBtn.addEventListener("click", hideAlert);

  // Preset buttons
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const presetKey = btn.getAttribute("data-preset");
      loadPreset(presetKey);
    });
  });

  // Form submit
  analyzeForm.addEventListener("submit", handleSubmit);
});
