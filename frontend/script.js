```javascript
const API_BASE = "";

const elements = {
    form: document.getElementById("analyzeForm"),
    sender: document.getElementById("sender"),
    subject: document.getElementById("subject"),
    message: document.getElementById("message"),
    charCount: document.getElementById("charCount"),
    analyzeButton: document.getElementById("analyzeButton"),
    resetButton: document.getElementById("resetButton"),
    results: document.getElementById("results"),
    errorContainer: document.getElementById("errorContainer"),
    backendStatus: document.getElementById("backendStatus"),
    mcpStatus: document.getElementById("mcpStatus"),
    riskScore: document.getElementById("riskScore"),
    riskFill: document.getElementById("riskFill"),
    classification: document.getElementById("classification"),
    severity: document.getElementById("severity"),
    summary: document.getElementById("summary"),
    indicators: document.getElementById("indicators"),
    reasons: document.getElementById("reasons"),
    recommendedAction: document.getElementById("recommendedAction"),
    analysisSteps: document.getElementById("analysisSteps"),
    toolEvidence: document.getElementById("toolEvidence")
};

const escapeHTML = (value) => {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
};

function showError(message) {
    if (!elements.errorContainer) return;

    elements.errorContainer.textContent = message;
    elements.errorContainer.classList.add("visible");
}

function hideError() {
    if (!elements.errorContainer) return;

    elements.errorContainer.textContent = "";
    elements.errorContainer.classList.remove("visible");
}

function setLoading(isLoading) {
    if (!elements.analyzeButton) return;

    elements.analyzeButton.disabled = isLoading;

    if (isLoading) {
        elements.analyzeButton.dataset.originalText =
            elements.analyzeButton.textContent;
        elements.analyzeButton.textContent = "Analyzing...";
    } else {
        elements.analyzeButton.textContent =
            elements.analyzeButton.dataset.originalText || "Analyze Message";
    }
}

function updateCharacterCount() {
    if (!elements.message || !elements.charCount) return;

    elements.charCount.textContent = elements.message.value.length;
}

function updateBackendStatus(online) {
    if (!elements.backendStatus) return;

    if (online) {
        elements.backendStatus.textContent = "BACKEND: ONLINE";
        elements.backendStatus.classList.remove("offline");
        elements.backendStatus.classList.add("online");
    } else {
        elements.backendStatus.textContent = "BACKEND: OFFLINE";
        elements.backendStatus.classList.remove("online");
        elements.backendStatus.classList.add("offline");
    }
}

function updateMCPStatus(status) {
    if (!elements.mcpStatus) return;

    const normalized = String(status || "").toLowerCase();

    if (
        normalized.includes("connected") ||
        normalized.includes("available") ||
        normalized.includes("local")
    ) {
        elements.mcpStatus.textContent = "MCP: CONNECTED";
        elements.mcpStatus.classList.remove("offline");
        elements.mcpStatus.classList.add("online");
    } else {
        elements.mcpStatus.textContent = "MCP: UNAVAILABLE";
        elements.mcpStatus.classList.remove("online");
        elements.mcpStatus.classList.add("offline");
    }
}

async function checkBackendHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`, {
            method: "GET",
            headers: {
                Accept: "application/json"
            }
        });

        if (!response.ok) {
            throw new Error(`Health check failed: HTTP ${response.status}`);
        }

        updateBackendStatus(true);
        return true;
    } catch (error) {
        console.error("Backend health check failed:", error);
        updateBackendStatus(false);
        return false;
    }
}

async function checkMCPStatus() {
    try {
        const response = await fetch(`${API_BASE}/mcp/status`, {
            method: "GET",
            headers: {
                Accept: "application/json"
            }
        });

        if (!response.ok) {
            throw new Error(`MCP status failed: HTTP ${response.status}`);
        }

        const data = await response.json();

        updateMCPStatus(data.status);

        return data;
    } catch (error) {
        console.error("MCP status check failed:", error);
        updateMCPStatus("unavailable");
        return null;
    }
}

function renderRiskScore(score) {
    const numericScore = Math.max(
        0,
        Math.min(100, Number(score) || 0)
    );

    if (elements.riskScore) {
        elements.riskScore.textContent = numericScore;
    }

    if (elements.riskFill) {
        elements.riskFill.style.width = `${numericScore}%`;
    }
}

function renderClassification(value) {
    if (!elements.classification) return;

    const classification = String(value || "UNKNOWN").toUpperCase();

    elements.classification.textContent = classification;
    elements.classification.className = "classification-badge";

    elements.classification.classList.add(
        classification.toLowerCase()
    );
}

function renderSeverity(value) {
    if (!elements.severity) return;

    const severity = String(value || "UNKNOWN").toUpperCase();

    elements.severity.textContent = severity;
    elements.severity.className = "severity-badge";

    elements.severity.classList.add(
        severity.toLowerCase()
    );
}

function renderList(container, items, emptyMessage = "None detected.") {
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(items) || items.length === 0) {
        const item = document.createElement("li");
        item.textContent = emptyMessage;
        container.appendChild(item);
        return;
    }

    items.forEach((itemValue) => {
        const item = document.createElement("li");
        item.textContent = String(itemValue);
        container.appendChild(item);
    });
}

function renderIndicators(indicators) {
    if (!elements.indicators) return;

    elements.indicators.innerHTML = "";

    if (!Array.isArray(indicators) || indicators.length === 0) {
        const span = document.createElement("span");
        span.textContent = "No major threat indicators detected.";
        elements.indicators.appendChild(span);
        return;
    }

    indicators.forEach((indicator) => {
        const tag = document.createElement("span");
        tag.className = "indicator-tag";
        tag.textContent = String(indicator);
        elements.indicators.appendChild(tag);
    });
}

function renderToolEvidence(toolEvidence) {
    if (!elements.toolEvidence) return;

    elements.toolEvidence.innerHTML = "";

    if (!Array.isArray(toolEvidence) || toolEvidence.length === 0) {
        const empty = document.createElement("div");
        empty.className = "tool-evidence-empty";
        empty.textContent = "No additional MCP tools were required.";
        elements.toolEvidence.appendChild(empty);
        return;
    }

    toolEvidence.forEach((evidence) => {
        const card = document.createElement("div");
        card.className = "tool-evidence-card";

        const title = document.createElement("h4");
        title.textContent =
            evidence.tool ||
            evidence.name ||
            "Security Tool";

        const risk = document.createElement("div");
        risk.className = "tool-risk";

        risk.textContent =
            evidence.risk_level ||
            evidence.risk ||
            "ANALYZED";

        card.appendChild(title);
        card.appendChild(risk);

        if (Array.isArray(evidence.signals)) {
            const signalList = document.createElement("ul");

            evidence.signals.forEach((signal) => {
                const li = document.createElement("li");
                li.textContent = String(signal);
                signalList.appendChild(li);
            });

            card.appendChild(signalList);
        }

        elements.toolEvidence.appendChild(card);
    });
}

function renderAnalysisSteps(steps) {
    if (!elements.analysisSteps) return;

    elements.analysisSteps.innerHTML = "";

    if (!Array.isArray(steps) || steps.length === 0) {
        const item = document.createElement("div");
        item.className = "analysis-step";
        item.textContent = "Analysis completed.";
        elements.analysisSteps.appendChild(item);
        return;
    }

    steps.forEach((step, index) => {
        const item = document.createElement("div");
        item.className = "analysis-step";

        const number = document.createElement("span");
        number.className = "step-number";
        number.textContent = index + 1;

        const text = document.createElement("span");
        text.textContent = String(step);

        item.appendChild(number);
        item.appendChild(text);

        elements.analysisSteps.appendChild(item);
    });
}

function renderResults(data) {
    renderRiskScore(data.risk_score);
    renderClassification(data.classification);
    renderSeverity(data.severity);

    if (elements.summary) {
        elements.summary.textContent =
            data.summary || "No summary available.";
    }

    if (elements.recommendedAction) {
        elements.recommendedAction.textContent =
            data.recommended_action ||
            "Review the message carefully before taking action.";
    }

    renderIndicators(data.indicators);
    renderList(elements.reasons, data.reasons);
    renderAnalysisSteps(data.analysis_steps);
    renderToolEvidence(data.tool_evidence);

    if (elements.results) {
        elements.results.hidden = false;
        elements.results.classList.add("visible");

        elements.results.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}

async function analyzeMessage(event) {
    event.preventDefault();

    hideError();

    const sender = elements.sender?.value.trim() || "";
    const subject = elements.subject?.value.trim() || "";
    const message = elements.message?.value.trim() || "";

    if (!message) {
        showError("Please enter a message to analyze.");
        return;
    }

    setLoading(true);

    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json"
            },
            body: JSON.stringify({
                sender,
                subject,
                message
            })
        });

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error(
                `Server returned an invalid response (HTTP ${response.status}).`
            );
        }

        if (!response.ok) {
            const detail =
                data?.detail ||
                data?.message ||
                `Analysis failed with HTTP ${response.status}.`;

            throw new Error(detail);
        }

        renderResults(data);
    } catch (error) {
        console.error("Analysis error:", error);

        showError(
            error.message ||
            "Unable to connect to the backend. Please try again."
        );
    } finally {
        setLoading(false);
    }
}

function resetForm() {
    if (elements.form) {
        elements.form.reset();
    }

    updateCharacterCount();
    hideError();

    if (elements.results) {
        elements.results.hidden = true;
        elements.results.classList.remove("visible");
    }

    if (elements.riskScore) {
        elements.riskScore.textContent = "0";
    }

    if (elements.riskFill) {
        elements.riskFill.style.width = "0%";
    }

    if (elements.indicators) {
        elements.indicators.innerHTML = "";
    }

    if (elements.reasons) {
        elements.reasons.innerHTML = "";
    }

    if (elements.analysisSteps) {
        elements.analysisSteps.innerHTML = "";
    }

    if (elements.toolEvidence) {
        elements.toolEvidence.innerHTML = "";
    }
}

function loadPreset(preset) {
    if (!preset) return;

    if (elements.sender) {
        elements.sender.value = preset.sender || "";
    }

    if (elements.subject) {
        elements.subject.value = preset.subject || "";
    }

    if (elements.message) {
        elements.message.value = preset.message || "";
    }

    updateCharacterCount();
    hideError();

    if (elements.results) {
        elements.results.hidden = true;
        elements.results.classList.remove("visible");
    }
}

document.addEventListener("DOMContentLoaded", async () => {
    if (elements.message) {
        elements.message.addEventListener(
            "input",
            updateCharacterCount
        );
    }

    if (elements.form) {
        elements.form.addEventListener(
            "submit",
            analyzeMessage
        );
    }

    if (elements.resetButton) {
        elements.resetButton.addEventListener(
            "click",
            resetForm
        );
    }

    updateCharacterCount();

    await Promise.all([
        checkBackendHealth(),
        checkMCPStatus()
    ]);

    /*
     * Preset buttons:
     *
     * If your HTML buttons contain a data-preset attribute,
     * the corresponding preset can be loaded here.
     */
    document
        .querySelectorAll("[data-preset]")
        .forEach((button) => {
            button.addEventListener("click", () => {
                const presetName =
                    button.dataset.preset;

                const preset =
                    window.PHISHGUARD_PRESETS?.[presetName];

                if (preset) {
                    loadPreset(preset);
                }
            });
        });
});
```
