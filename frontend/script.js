async function checkBackendHealth() {
    const statusElement =
        document.getElementById("backendStatus") ||
        document.getElementById("apiStatus");

    if (!statusElement) {
        console.error("Backend status element not found.");
        return;
    }

    statusElement.textContent = "API: CHECKING...";

    try {
        const response = await fetch("/health", {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status === "healthy") {
            statusElement.textContent = "API: ONLINE";
            statusElement.classList.remove("offline", "checking");
            statusElement.classList.add("online");
        } else {
            throw new Error("Backend is not healthy");
        }

    } catch (error) {
        console.error("Backend health check failed:", error);

        statusElement.textContent = "API: OFFLINE";
        statusElement.classList.remove("online", "checking");
        statusElement.classList.add("offline");
    }
}


async function checkMCPStatus() {
    const statusElement =
        document.getElementById("mcpStatus");

    if (!statusElement) {
        console.error("MCP status element not found.");
        return;
    }

    statusElement.textContent = "MCP: CHECKING...";

    try {
        const response = await fetch("/mcp/status", {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        console.log("MCP status:", data);

        const status = String(data.status || "").toLowerCase();

        if (
            status === "connected" ||
            status === "available" ||
            status === "local" ||
            data.tools
        ) {
            statusElement.textContent = "MCP: CONNECTED";
            statusElement.classList.remove("offline", "checking");
            statusElement.classList.add("online");
        } else {
            statusElement.textContent = "MCP: OFFLINE";
            statusElement.classList.remove("online", "checking");
            statusElement.classList.add("offline");
        }

    } catch (error) {
        console.error("MCP status check failed:", error);

        statusElement.textContent = "MCP: OFFLINE";
        statusElement.classList.remove("online", "checking");
        statusElement.classList.add("offline");
    }
}
