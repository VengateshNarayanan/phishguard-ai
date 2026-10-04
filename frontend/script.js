
"use strict";

/*
 * PhishGuard AI
 * Frontend Controller
 *
 * IMPORTANT:
 * The frontend and FastAPI backend are deployed together.
 * Therefore relative API paths are used:
 *
 *   /health
 *   /mcp/status
 *   /analyze
 *
 * This allows the application to work for every visitor.
 */

const API_BASE = "";

// ============================================================
// DOM ELEMENTS
// ============================================================

const elements = {
    form: document.getElementById("analyze-form"),

    sender: document.getElementById("sender-input"),
    subject: document.getElementById("subject-input"),
    message: document.getElementById("message-input"),

    charCounter: document.getElementById("char-counter"),

    clearButton: document.getElementById("clear-btn"),
    submitButton: document.getElementById("submit-btn"),
    submitSpinner: document.getElementById("submit-spinner"),
    submitIcon: document.getElementById("submit-icon"),
    submitLabel: document.getElementById("submit-label"),

    // API status
    statusDot: document.getElementById("status-dot"),
    statusText: document.getElementById("status-text"),

    // MCP status
    mcpStatusDot: document.getElementById("mcp-status-dot"),
    mcpStatusText: document.getElementById("mcp-status-text"),

    // Alert
    alertBanner: document.getElementById("alert-banner"),
    alertIcon: document.getElementById("alert-icon"),
    alertMessage: document.getElementById("alert-message"),
    alertCloseButton: document.getElementById("alert-close-btn"),

    // Results
    resultsCard: document.getElementById("results-card"),
    resultsIdle: document.getElementById("results-idle"),
    resultsContent: document.getElementById("results-content"),

    resultScore: document.getElementById("result-score"),
    scoreCircle: document.getElementById("score-circle"),

    resultSeverity: document.getElementById("result-severity"),
    resultClassification: document.getElementById("result-classification"),

    resultSummary: document.getElementById("result-summary"),

    investigationSteps:
        document.getElementById("investigation-steps-list"),

    toolEvidence:
        document.getElementById("tool-evidence-grid"),

    resultIndicators:
        document.getElementById("result-indicators"),

    resultReasons:
        document.getElementById("result-reasons"),

    resultAction:
        document.getElementById("result-action"),

    resultActionBox:
        document.getElementById("result-action-box")
};


// ============================================================
// PRESET DATA
// ============================================================

const PRESETS = {

    safe: {
        sender: "team@company.com",
        subject: "Team Meeting - Tomorrow at 10 AM",
        message:
            "Hi team,\n\n" +
            "This is a reminder that our weekly team meeting is scheduled " +
            "for tomorrow at 10 AM in the conference room.\n\n" +
            "Regards,\n" +
            "Team Lead"
    },

    suspicious: {
        sender: "delivery-update@shipping-notice.com",
        subject: "Delivery Attempt Failed",
        message:
            "Dear Customer,\n\n" +
            "We attempted to deliver your package today but were unable " +
            "to complete the delivery. Please confirm your delivery " +
            "details using the link below.\n\n" +
            "Thank you."
    },

    phishing: {
        sender: "security-alert@paypal-verify-alert.com",
        subject: "URGENT: Your account will be suspended",
        message:
            "URGENT SECURITY ALERT!\n\n" +
            "We detected unusual activity on your account. " +
            "Your account will be permanently suspended within 24 hours " +
            "unless you verify your identity immediately.\n\n" +
            "Verify your account now:\n" +
            "http://paypal-verify-login.ru/auth\n\n" +
            "Failure to verify will result in permanent account closure."
    },

    scam: {
        sender: "winner@crypto-rewards.xyz",
        subject: "Congratulations! You Won 5 Bitcoin",
        message:
            "CONGRATULATIONS!!!\n\n" +
            "You have been selected as the winner of our exclusive " +
            "crypto lottery and have won 5 BTC.\n\n" +
            "To claim your reward, send a small processing fee immediately " +
            "and provide your cryptocurrency wallet information.\n\n" +
            "Act now before your reward expires!"
    },

    headers: {
        sender: "support@secure-bank.com",
        subject: "Important Security Notification",
        message:
            "From: support@secure-bank.com\n" +
            "Reply-To: attacker@malicious-domain.ru\n" +
            "Return-Path: bounce@malicious-domain.ru\n" +
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n" +
            "Received: from suspicious-host.ru\n\n" +
            "Your account requires immediate verification."
    }
};


// ============================================================
// ALERT SYSTEM
// ============================================================

function showAlert(message, type = "error") {

    if (!elements.alertBanner) {
        alert(message);
        return;
    }

    elements.alertBanner.classList.remove(
        "hidden",
        "alert-success",
        "alert-warning",
        "alert-error"
    );

    elements.alertBanner.classList.add(
        `alert-${type}`
    );

    if (elements.alertMessage) {
        elements.alertMessage.textContent = message;
    }

    if (elements.alertIcon) {

        if (type === "success") {
            elements.alertIcon.textContent = "✓";
        } else if (type === "warning") {
            elements.alertIcon.textContent = "⚠️";
        } else {
            elements.alertIcon.textContent = "⚠️";
        }
    }
}


function hideAlert() {

    if (!elements.alertBanner) {
        return;
    }

    elements.alertBanner.classList.add("hidden");
}


// ============================================================
// API STATUS
// ============================================================

async function checkAPIStatus() {

    if (!elements.statusText || !elements.statusDot) {
        console.error("API status elements not found.");
        return;
    }

    // Initial state
    elements.statusText.textContent = "API: Checking...";

    elements.statusDot.classList.remove(
        "online",
        "offline"
    );

    elements.statusDot.classList.add("checking");

    try {

        const response = await fetch(
            `${API_BASE}/health`,
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            }
        );

        if (!response.ok) {
            throw new Error(
                `Health endpoint returned HTTP ${response.status}`
            );
        }

        const data = await response.json();

        console.log("API health response:", data);

        if (data.status === "healthy") {

            elements.statusText.textContent =
                "API: Online";

            elements.statusDot.classList.remove(
                "checking",
                "offline"
            );

            elements.statusDot.classList.add("online");

        } else {

            throw new Error(
                "Backend did not report healthy status."
            );
        }

    } catch (error) {

        console.error(
            "API health check failed:",
            error
        );

        elements.statusText.textContent =
            "API: Offline";

        elements.statusDot.classList.remove(
            "checking",
            "online"
        );

        elements.statusDot.classList.add(
            "offline"
        );
    }
}


// ============================================================
// MCP STATUS
// ============================================================

async function checkMCPStatus() {

    if (!elements.mcpStatusText ||
        !elements.mcpStatusDot) {

        console.error(
            "MCP status elements not found."
        );

        return;
    }

    elements.mcpStatusText.textContent =
        "MCP: Checking...";

    elements.mcpStatusDot.classList.remove(
        "online",
        "offline"
    );

    elements.mcpStatusDot.classList.add(
        "checking"
    );

    try {

        const response = await fetch(
            `${API_BASE}/mcp/status`,
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            }
        );

        if (!response.ok) {
            throw new Error(
                `MCP status returned HTTP ${response.status}`
            );
        }

        const data = await response.json();

        console.log(
            "MCP status response:",
            data
        );

        const status =
            String(data.status || "")
                .toLowerCase();

        /*
         * Different Phase 2 implementations may return:
         *
         * { "status": "connected" }
         * { "status": "available" }
         * { "status": "local" }
         *
         * or include a tools array.
         */

        const connected =
            status === "connected" ||
            status === "available" ||
            status === "local" ||
            Array.isArray(data.tools);

        if (connected) {

            elements.mcpStatusText.textContent =
                "MCP: Connected";

            elements.mcpStatusDot.classList.remove(
                "checking",
                "offline"
            );

            elements.mcpStatusDot.classList.add(
                "online"
            );

        } else {

            elements.mcpStatusText.textContent =
                "MCP: Offline";

            elements.mcpStatusDot.classList.remove(
                "checking",
                "online"
            );

            elements.mcpStatusDot.classList.add(
                "offline"
            );
        }

    } catch (error) {

        console.error(
            "MCP status check failed:",
            error
        );

        elements.mcpStatusText.textContent =
            "MCP: Offline";

        elements.mcpStatusDot.classList.remove(
            "checking",
            "online"
        );

        elements.mcpStatusDot.classList.add(
            "offline"
        );
    }
}


// ============================================================
// CHARACTER COUNTER
// ============================================================

function updateCharacterCounter() {

    if (!elements.message ||
        !elements.charCounter) {
        return;
    }

    const count =
        elements.message.value.length;

    elements.charCounter.textContent =
        `${count} characters`;
}


// ============================================================
// LOADING STATE
// ============================================================

function setLoading(loading) {

    if (!elements.submitButton) {
        return;
    }

    elements.submitButton.disabled =
        loading;

    if (loading) {

        if (elements.submitSpinner) {
            elements.submitSpinner.classList.remove(
                "hidden"
            );
        }

        if (elements.submitIcon) {
            elements.submitIcon.classList.add(
                "hidden"
            );
        }

        if (elements.submitLabel) {
            elements.submitLabel.textContent =
                "Security Agent Analyzing...";
        }

    } else {

        if (elements.submitSpinner) {
            elements.submitSpinner.classList.add(
                "hidden"
            );
        }

        if (elements.submitIcon) {
            elements.submitIcon.classList.remove(
                "hidden"
            );
        }

        if (elements.submitLabel) {
            elements.submitLabel.textContent =
                "Analyze with Security Agent";
        }
    }
}


// ============================================================
// PRESET LOADER
// ============================================================

function loadPreset(name) {

    const preset =
        PRESETS[name];

    if (!preset) {
        console.warn(
            `Preset "${name}" not found.`
        );
        return;
    }

    elements.sender.value =
        preset.sender || "";

    elements.subject.value =
        preset.subject || "";

    elements.message.value =
        preset.message || "";

    updateCharacterCounter();

    hideAlert();

    console.log(
        `Loaded preset: ${name}`
    );
}


// ============================================================
// CLEAR FORM
// ============================================================

function clearForm() {

    if (elements.form) {
        elements.form.reset();
    }

    updateCharacterCounter();

    hideAlert();

    hideResults();
}


// ============================================================
// HIDE RESULTS
// ============================================================

function hideResults() {

    if (elements.resultsContent) {
        elements.resultsContent.classList.add(
            "hidden"
        );
    }

    if (elements.resultsIdle) {
        elements.resultsIdle.classList.remove(
            "hidden"
        );
    }
}


// ============================================================
// SHOW RESULTS
// ============================================================

function showResults() {

    if (elements.resultsIdle) {
        elements.resultsIdle.classList.add(
            "hidden"
        );
    }

    if (elements.resultsContent) {
        elements.resultsContent.classList.remove(
            "hidden"
        );
    }
}


// ============================================================
// RISK SCORE
// ============================================================

function renderRiskScore(score) {

    let numericScore =
        Number(score);

    if (!Number.isFinite(numericScore)) {
        numericScore = 0;
    }

    numericScore =
        Math.max(
            0,
            Math.min(
                100,
                Math.round(numericScore)
            )
        );

    if (elements.resultScore) {
        elements.resultScore.textContent =
            numericScore;
    }

    if (elements.scoreCircle) {

        /*
         * CSS can use this custom property
         * if supported.
         */

        elements.scoreCircle.style
            .setProperty(
                "--risk-score",
                numericScore
            );
    }
}


// ============================================================
// CLASSIFICATION
// ============================================================

function renderClassification(classification) {

    if (!elements.resultClassification) {
        return;
    }

    const value =
        String(
            classification || "UNKNOWN"
        ).toUpperCase();

    elements.resultClassification.textContent =
        value;

    elements.resultClassification.className =
        "classification-badge";

    elements.resultClassification.classList.add(
        value.toLowerCase()
    );
}


// ============================================================
// SEVERITY
// ============================================================

function renderSeverity(severity) {

    if (!elements.resultSeverity) {
        return;
    }

    const value =
        String(
            severity || "UNKNOWN"
        ).toUpperCase();

    elements.resultSeverity.textContent =
        value;

    elements.resultSeverity.className =
        "severity-pill";

    elements.resultSeverity.classList.add(
        value.toLowerCase()
    );
}


// ============================================================
// EXECUTIVE SUMMARY
// ============================================================

function renderSummary(summary) {

    if (!elements.resultSummary) {
        return;
    }

    elements.resultSummary.textContent =
        summary ||
        "No security summary was provided.";
}


// ============================================================
// INDICATORS
// ============================================================

function renderIndicators(indicators) {

    if (!elements.resultIndicators) {
        return;
    }

    elements.resultIndicators.innerHTML = "";

    if (
        !Array.isArray(indicators) ||
        indicators.length === 0
    ) {

        const empty =
            document.createElement("span");

        empty.className =
            "indicator-tag";

        empty.textContent =
            "No major indicators detected.";

        elements.resultIndicators.appendChild(
            empty
        );

        return;
    }

    indicators.forEach(
        (indicator) => {

            const tag =
                document.createElement("span");

            tag.className =
                "indicator-tag";

            /*
             * textContent is intentionally used
             * instead of innerHTML to prevent XSS.
             */

            tag.textContent =
                String(indicator);

            elements.resultIndicators.appendChild(
                tag
            );
        }
    );
}


// ============================================================
// REASONS
// ============================================================

function renderReasons(reasons) {

    if (!elements.resultReasons) {
        return;
    }

    elements.resultReasons.innerHTML = "";

    if (
        !Array.isArray(reasons) ||
        reasons.length === 0
    ) {

        const li =
            document.createElement("li");

        li.textContent =
            "No additional reasons were provided.";

        elements.resultReasons.appendChild(
            li
        );

        return;
    }

    reasons.forEach(
        (reason) => {

            const li =
                document.createElement("li");

            li.textContent =
                String(reason);

            elements.resultReasons.appendChild(
                li
            );
        }
    );
}


// ============================================================
// INVESTIGATION STEPS
// ============================================================

function renderInvestigationSteps(steps) {

    if (!elements.investigationSteps) {
        return;
    }

    elements.investigationSteps.innerHTML = "";

    if (
        !Array.isArray(steps) ||
        steps.length === 0
    ) {

        const li =
            document.createElement("li");

        li.textContent =
            "Security Agent completed the analysis.";

        elements.investigationSteps.appendChild(
            li
        );

        return;
    }

    steps.forEach(
        (step, index) => {

            const li =
                document.createElement("li");

            li.textContent =
                `${index + 1}. ${String(step)}`;

            elements.investigationSteps.appendChild(
                li
            );
        }
    );
}


// ============================================================
// MCP TOOL EVIDENCE
// ============================================================

function renderToolEvidence(toolEvidence) {

    if (!elements.toolEvidence) {
        return;
    }

    elements.toolEvidence.innerHTML = "";

    if (
        !Array.isArray(toolEvidence) ||
        toolEvidence.length === 0
    ) {

        const empty =
            document.createElement("div");

        empty.className =
            "tool-evidence-empty";

        empty.textContent =
            "No additional MCP tools were required for this message.";

        elements.toolEvidence.appendChild(
            empty
        );

        return;
    }

    toolEvidence.forEach(
        (evidence) => {

            const card =
                document.createElement("div");

            card.className =
                "tool-evidence-card";

            const title =
                document.createElement("h5");

            title.textContent =
                evidence.tool ||
                evidence.tool_name ||
                evidence.name ||
                "MCP Security Tool";

            card.appendChild(title);

            if (evidence.risk_level) {

                const risk =
                    document.createElement("span");

                risk.className =
                    "tool-risk-level";

                risk.textContent =
                    String(
                        evidence.risk_level
                    ).toUpperCase();

                card.appendChild(risk);
            }

            if (evidence.summary) {

                const summary =
                    document.createElement("p");

                summary.textContent =
                    String(
                        evidence.summary
                    );

                card.appendChild(summary);
            }

            if (
                Array.isArray(
                    evidence.signals
                )
            ) {

                const list =
                    document.createElement("ul");

                evidence.signals.forEach(
                    (signal) => {

                        const li =
                            document.createElement("li");

                        li.textContent =
                            String(signal);

                        list.appendChild(li);
                    }
                );

                card.appendChild(list);
            }

            elements.toolEvidence.appendChild(
                card
            );
        }
    );
}


// ============================================================
// RENDER COMPLETE RESULT
// ============================================================

function renderResults(data) {

    console.log(
        "Analysis response:",
        data
    );

    renderRiskScore(
        data.risk_score
    );

    renderClassification(
        data.classification
    );

    renderSeverity(
        data.severity
    );

    renderSummary(
        data.summary
    );

    renderIndicators(
        data.indicators
    );

    renderReasons(
        data.reasons
    );

    renderInvestigationSteps(
        data.analysis_steps
    );

    renderToolEvidence(
        data.tool_evidence
    );

    if (elements.resultAction) {

        elements.resultAction.textContent =
            data.recommended_action ||
            "Review the message carefully before taking any action.";
    }

    showResults();

    if (elements.resultsCard) {

        elements.resultsCard.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}


// ============================================================
// ANALYZE MESSAGE
// ============================================================

async function analyzeMessage(event) {

    event.preventDefault();

    hideAlert();

    const sender =
        elements.sender.value.trim();

    const subject =
        elements.subject.value.trim();

    const message =
        elements.message.value.trim();

    if (!message) {

        showAlert(
            "Please enter a message before starting the security analysis.",
            "warning"
        );

        elements.message.focus();

        return;
    }

    setLoading(true);

    try {

        console.log(
            "Sending analysis request to:",
            `${API_BASE}/analyze`
        );

        const response =
            await fetch(
                `${API_BASE}/analyze`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json"
                    },

                    body: JSON.stringify({
                        sender,
                        subject,
                        message
                    })
                }
            );

        let data;

        try {

            data =
                await response.json();

        } catch {

            throw new Error(
                `The server returned an invalid response (HTTP ${response.status}).`
            );
        }

        if (!response.ok) {

            let errorMessage =
                `Analysis failed (HTTP ${response.status}).`;

            if (data.detail) {

                if (
                    typeof data.detail ===
                    "string"
                ) {

                    errorMessage =
                        data.detail;

                } else {

                    errorMessage =
                        JSON.stringify(
                            data.detail
                        );
                }
            }

            throw new Error(
                errorMessage
            );
        }

        renderResults(data);

        showAlert(
            "Security analysis completed successfully.",
            "success"
        );

    } catch (error) {

        console.error(
            "Analysis request failed:",
            error
        );

        showAlert(
            error.message ||
            "Unable to connect to the PhishGuard backend.",
            "error"
        );

    } finally {

        setLoading(false);
    }
}


// ============================================================
// EVENT LISTENERS
// ============================================================

function initializeEventListeners() {

    // Analyze form
    if (elements.form) {

        elements.form.addEventListener(
            "submit",
            analyzeMessage
        );
    }

    // Clear button
    if (elements.clearButton) {

        elements.clearButton.addEventListener(
            "click",
            clearForm
        );
    }

    // Character counter
    if (elements.message) {

        elements.message.addEventListener(
            "input",
            updateCharacterCounter
        );
    }

    // Alert close
    if (elements.alertCloseButton) {

        elements.alertCloseButton.addEventListener(
            "click",
            hideAlert
        );
    }

    // Preset buttons
    document
        .querySelectorAll(
            "[data-preset]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const presetName =
                            button.dataset.preset;

                        loadPreset(
                            presetName
                        );
                    }
                );
            }
        );
}


// ============================================================
// APPLICATION STARTUP
// ============================================================

async function initializeApplication() {

    console.log(
        "PhishGuard AI frontend initializing..."
    );

    updateCharacterCounter();

    initializeEventListeners();

    /*
     * Run both status checks independently.
     *
     * If one endpoint fails, the other still updates.
     */

    await Promise.allSettled([
        checkAPIStatus(),
        checkMCPStatus()
    ]);

    console.log(
        "PhishGuard AI frontend initialized."
    );
}


// Start application
document.addEventListener(
    "DOMContentLoaded",
    initializeApplication
);

