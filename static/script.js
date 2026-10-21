/**
 * SDN Intelligent Traffic Management and Access Control
 * Client-Side Controller & Presentation Interface
 */

// Node coordinates on the SVG canvas for path visualization
const NODE_COORDINATES = {
    "H1": { x: 100, y: 100 },
    "H2": { x: 100, y: 230 },
    "H3": { x: 500, y: 280 },
    "H4": { x: 860, y: 100 },
    "H5": { x: 860, y: 230 },
    "S1": { x: 255, y: 160 },
    "S2": { x: 500, y: 110 },
    "S3": { x: 735, y: 160 }
};

// Initialize Dashboard upon DOM load
document.addEventListener("DOMContentLoaded", () => {
    fetchStats();
    fetchRules();
    fetchLogs();
});

// -------------------------------------------------------------
// SECTION A: Metrics and Statistics Sync
// -------------------------------------------------------------
async function fetchStats() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Failed to load statistics");
        const data = await response.json();

        document.getElementById("stat-switches").innerText = data.switches_count;
        document.getElementById("stat-hosts").innerText = data.hosts_count;
        document.getElementById("stat-total-packets").innerText = data.total_packets;
        document.getElementById("stat-allowed-packets").innerText = data.allowed_packets;
        document.getElementById("stat-blocked-packets").innerText = data.blocked_packets;
        document.getElementById("stat-active-rules").innerText = data.active_rules_count;
        document.getElementById("rules-count-badge").innerText = `${data.active_rules_count} Active`;
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

// -------------------------------------------------------------
// SECTION C: Packet Simulator & Demo Presets
// -------------------------------------------------------------
function applyPreset(src, dst, proto, port) {
    document.getElementById("src-ip").value = src;
    document.getElementById("dst-ip").value = dst;
    document.getElementById("protocol").value = proto;
    document.getElementById("dst-port").value = port;
    showToast(`Loaded Preset: ${src} → ${dst} (${proto}:${port})`, "info");
}

async function handleSendPacket(event) {
    event.preventDefault();

    const srcIp = document.getElementById("src-ip").value.trim();
    const dstIp = document.getElementById("dst-ip").value.trim();
    const protocol = document.getElementById("protocol").value;
    const dstPort = document.getElementById("dst-port").value.trim();
    const sendBtn = document.getElementById("btn-send-packet");

    if (!srcIp || !dstIp || !dstPort) {
        showToast("Please provide all packet header fields.", "error");
        return;
    }

    sendBtn.disabled = true;
    sendBtn.innerText = "Simulating SDN Ingress...";

    try {
        const response = await fetch("/api/simulate-packet", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                src_ip: srcIp,
                dst_ip: dstIp,
                protocol: protocol,
                dst_port: parseInt(dstPort, 10)
            })
        });

        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || "Simulation failed", "error");
            sendBtn.disabled = false;
            sendBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                </svg>
                Send Packet to SDN Controller
            `;
            return;
        }

        // Render decision result card
        renderSimulationResult(data);

        // Highlight paths or drops on SVG topology
        visualizePacketOnTopology(data);

        // Refresh stats and logs
        fetchStats();
        fetchLogs();

        const badgeType = data.decision === "ALLOWED" ? "success" : "error";
        showToast(`SDN Controller: Packet ${data.decision}`, badgeType);

    } catch (err) {
        console.error("Simulation error:", err);
        showToast("An unexpected error occurred during simulation.", "error");
    } finally {
        sendBtn.disabled = false;
        sendBtn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
            Send Packet to SDN Controller
        `;
    }
}

function renderSimulationResult(data) {
    const card = document.getElementById("simulation-result");
    const badge = document.getElementById("decision-badge");
    const ruleText = document.getElementById("decision-rule-text");
    const reasonText = document.getElementById("decision-reason");
    const pathBox = document.getElementById("path-flow-visual");
    const timeText = document.getElementById("decision-time");

    card.classList.remove("hidden");
    timeText.innerText = new Date().toLocaleTimeString();

    if (data.decision === "ALLOWED") {
        badge.className = "decision-badge badge-allowed";
        badge.innerText = "ALLOWED";
    } else {
        badge.className = "decision-badge badge-blocked";
        badge.innerText = "BLOCKED";
    }

    ruleText.innerText = `Matched Rule: ${data.matching_rule.id} (Prio ${data.matching_rule.priority})`;
    reasonText.innerText = data.reason;

    // Build hop elements
    pathBox.innerHTML = "";
    if (data.path && Array.isArray(data.path)) {
        data.path.forEach((hop, index) => {
            const hopSpan = document.createElement("span");
            hopSpan.className = "path-hop";

            if (hop.startsWith("S1") || hop.startsWith("S2") || hop.startsWith("S3")) {
                hopSpan.classList.add("switch-hop");
            } else if (hop.includes("DROPPED") || hop.includes("UNREACHABLE") || hop.includes("NO ROUTE")) {
                hopSpan.classList.add("drop-hop");
            }

            hopSpan.innerText = hop;
            pathBox.appendChild(hopSpan);

            if (index < data.path.length - 1) {
                const arrow = document.createElement("span");
                arrow.className = "path-arrow";
                arrow.innerText = "→";
                pathBox.appendChild(arrow);
            }
        });
    }
}

// -------------------------------------------------------------
// SECTION B: Interactive Topology Visualization
// -------------------------------------------------------------
function clearTopologyHighlights() {
    document.querySelectorAll(".topo-link, .host-link").forEach(el => {
        el.classList.remove("link-highlighted", "link-blocked");
    });
    document.querySelectorAll(".switch-rect").forEach(el => {
        el.style.stroke = "var(--cyan-glow)";
        el.style.filter = "drop-shadow(0 0 8px rgba(6, 182, 212, 0.4))";
    });
    const particle = document.getElementById("packet-particle");
    if (particle) {
        particle.style.opacity = "0";
    }
}

function visualizePacketOnTopology(data) {
    clearTopologyHighlights();

    const isAllowed = data.decision === "ALLOWED";
    const srcHost = data.packet.src_host;
    const dstHost = data.packet.dst_host;
    const hopNodes = data.hop_details ? data.hop_details.path_nodes : [];

    if (isAllowed) {
        // Highlight links in green
        // 1. Host to Switch
        if (srcHost && hopNodes[1]) {
            const hostLink = document.getElementById(`link-${srcHost}-${hopNodes[1]}`);
            if (hostLink) hostLink.classList.add("link-highlighted");
        }

        // 2. Inter-switch links
        const switches = data.hop_details.switches || [];
        for (let i = 0; i < switches.length - 1; i++) {
            const sA = switches[i];
            const sB = switches[i + 1];
            const swLink = document.getElementById(`link-${sA}-${sB}`) || document.getElementById(`link-${sB}-${sA}`);
            if (swLink) swLink.classList.add("link-highlighted");
        }

        // 3. Egress switch to target host
        if (dstHost && switches.length > 0) {
            const lastSw = switches[switches.length - 1];
            const destHostLink = document.getElementById(`link-${dstHost}-${lastSw}`);
            if (destHostLink) destHostLink.classList.add("link-highlighted");
        }

        // Animate particle across coordinates
        animatePacketParticle(hopNodes);

    } else {
        // Blocked: Show drop at ingress switch
        const dropPoint = data.hop_details ? data.hop_details.drop_point : "S1";
        const swRect = document.querySelector(`#node-${dropPoint} .switch-rect`);
        if (swRect) {
            swRect.style.stroke = "var(--rose-accent)";
            swRect.style.filter = "drop-shadow(0 0 16px rgba(244, 63, 94, 0.8))";
        }

        if (srcHost && dropPoint) {
            const hostLink = document.getElementById(`link-${srcHost}-${dropPoint}`);
            if (hostLink) hostLink.classList.add("link-blocked");
        }
    }

    // Auto clear after 4 seconds
    setTimeout(() => {
        clearTopologyHighlights();
    }, 4000);
}

function animatePacketParticle(nodes) {
    const particle = document.getElementById("packet-particle");
    if (!particle || !nodes || nodes.length < 2) return;

    const coords = nodes.map(n => NODE_COORDINATES[n]).filter(Boolean);
    if (coords.length < 2) return;

    particle.setAttribute("cx", coords[0].x);
    particle.setAttribute("cy", coords[0].y);
    particle.style.opacity = "1";

    let step = 0;
    const totalSteps = coords.length - 1;
    const durationPerHop = 450; // ms

    function moveHop() {
        if (step >= totalSteps) {
            setTimeout(() => { particle.style.opacity = "0"; }, 300);
            return;
        }

        const start = coords[step];
        const end = coords[step + 1];
        const startTime = performance.now();

        function stepAnimation(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / durationPerHop, 1);

            const currX = start.x + (end.x - start.x) * progress;
            const currY = start.y + (end.y - start.y) * progress;

            particle.setAttribute("cx", currX);
            particle.setAttribute("cy", currY);

            if (progress < 1) {
                requestAnimationFrame(stepAnimation);
            } else {
                step++;
                moveHop();
            }
        }
        requestAnimationFrame(stepAnimation);
    }

    moveHop();
}

// -------------------------------------------------------------
// SECTION D: IP Access Control Management
// -------------------------------------------------------------
async function fetchRules() {
    try {
        const response = await fetch("/api/rules");
        if (!response.ok) throw new Error("Failed to fetch rules");
        const rules = await response.json();

        renderAclRules(rules);
        renderFlowTable(rules);
    } catch (err) {
        console.error("Error fetching rules:", err);
    }
}

function renderAclRules(rules) {
    const container = document.getElementById("acl-rules-container");
    container.innerHTML = "";

    const userRules = rules.filter(r => !r.is_default);

    if (userRules.length === 0) {
        container.innerHTML = `<div class="empty-state">No custom blocking rules installed. Default permit policy is active.</div>`;
        return;
    }

    userRules.forEach(rule => {
        const card = document.createElement("div");
        card.className = "acl-rule-card";

        const isChecked = rule.is_active ? "checked" : "";
        const statusBadge = rule.is_active 
            ? `<span class="badge" style="background:var(--rose-bg); color:var(--rose-accent);">BLOCK ACTIVE</span>` 
            : `<span class="badge badge-neutral">DISABLED</span>`;

        card.innerHTML = `
            <div class="acl-rule-info">
                <div class="acl-rule-id-line">
                    <span class="rule-id-text">${rule.id}</span>
                    ${statusBadge}
                </div>
                <div class="acl-target-ip">DROP: ${rule.match.src_ip}</div>
                <div class="acl-desc-text">${rule.description || 'No description provided'}</div>
            </div>
            <div class="acl-rule-actions">
                <label class="toggle-switch" title="Toggle rule active state">
                    <input type="checkbox" ${isChecked} onchange="toggleRule('${rule.id}')">
                    <span class="toggle-slider"></span>
                </label>
                <button type="button" class="btn btn-outline-danger btn-sm" onclick="deleteRule('${rule.id}')" title="Delete rule">
                    ✕
                </button>
            </div>
        `;
        container.appendChild(card);
    });
}

async function handleAddRule(event) {
    event.preventDefault();

    const srcIp = document.getElementById("block-ip").value.trim();
    const desc = document.getElementById("block-desc").value.trim();

    if (!srcIp) {
        showToast("Please provide a Source IP to block.", "error");
        return;
    }

    try {
        const response = await fetch("/api/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ src_ip: srcIp, description: desc })
        });

        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || "Failed to add rule", "error");
            return;
        }

        showToast(`Rule Installed: DROP traffic from ${srcIp}`, "success");
        document.getElementById("block-ip").value = "";
        document.getElementById("block-desc").value = "";

        fetchRules();
        fetchStats();
        fetchLogs();
    } catch (err) {
        console.error("Error adding rule:", err);
        showToast("Failed to communicate with SDN controller.", "error");
    }
}

async function toggleRule(ruleId) {
    try {
        const response = await fetch(`/api/rules/${ruleId}/toggle`, {
            method: "PATCH"
        });
        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || "Failed to toggle rule", "error");
            return;
        }

        const state = data.rule.is_active ? "ENABLED" : "DISABLED";
        showToast(`Rule ${ruleId} is now ${state}`, "info");

        fetchRules();
        fetchStats();
        fetchLogs();
    } catch (err) {
        console.error("Error toggling rule:", err);
        showToast("Error updating rule status.", "error");
    }
}

async function deleteRule(ruleId) {
    try {
        const response = await fetch(`/api/rules/${ruleId}`, {
            method: "DELETE"
        });
        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || "Failed to remove rule", "error");
            return;
        }

        showToast(`Rule ${ruleId} deleted successfully`, "info");
        fetchRules();
        fetchStats();
        fetchLogs();
    } catch (err) {
        console.error("Error deleting rule:", err);
        showToast("Error deleting rule.", "error");
    }
}

// -------------------------------------------------------------
// SECTION E: SDN Flow-Rule Table
// -------------------------------------------------------------
function renderFlowTable(rules) {
    const tbody = document.getElementById("flow-rules-tbody");
    tbody.innerHTML = "";

    rules.forEach(rule => {
        const tr = document.createElement("tr");

        let actionBadge;
        if (rule.action === "DROP") {
            actionBadge = `<span class="badge" style="background:var(--rose-bg); color:var(--rose-accent); border:1px solid var(--rose-accent);">DROP</span>`;
        } else {
            actionBadge = `<span class="badge" style="background:var(--emerald-bg); color:var(--emerald-accent); border:1px solid var(--emerald-accent);">FORWARD</span>`;
        }

        let statusBadge;
        if (rule.is_active) {
            statusBadge = `<span class="pill pill-green">ACTIVE</span>`;
        } else {
            statusBadge = `<span class="badge badge-neutral">DISABLED</span>`;
        }

        let actionsHtml = "";
        if (rule.is_default) {
            actionsHtml = `<span class="text-muted" style="font-size:11px;">Default Policy</span>`;
        } else {
            actionsHtml = `
                <button type="button" class="btn btn-secondary btn-sm" onclick="toggleRule('${rule.id}')">Toggle</button>
                <button type="button" class="btn btn-outline-danger btn-sm" onclick="deleteRule('${rule.id}')">Delete</button>
            `;
        }

        tr.innerHTML = `
            <td><code class="mono" style="color:var(--blue-accent); font-weight:700;">${rule.id}</code></td>
            <td><strong>${rule.priority}</strong></td>
            <td><code class="mono">${rule.match_display}</code></td>
            <td>${actionBadge}</td>
            <td>${statusBadge}</td>
            <td><span style="color:var(--text-secondary); font-size:12px;">${rule.description}</span></td>
            <td>${actionsHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

// -------------------------------------------------------------
// SECTION F: Traffic Activity Log & Clear Confirmation
// -------------------------------------------------------------
async function fetchLogs() {
    try {
        const response = await fetch("/api/logs");
        if (!response.ok) throw new Error("Failed to fetch logs");
        const logs = await response.json();
        renderLogsTable(logs);
    } catch (err) {
        console.error("Error fetching logs:", err);
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("activity-log-tbody");
    tbody.innerHTML = "";

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">No packet activity recorded yet. Send a simulated packet above to generate traffic logs.</td>
            </tr>
        `;
        return;
    }

    logs.forEach(log => {
        const tr = document.createElement("tr");

        let decisionBadge = "";
        if (log.decision === "ALLOWED") {
            decisionBadge = `<span class="badge" style="background:var(--emerald-bg); color:var(--emerald-accent);">ALLOW</span>`;
        } else if (log.decision === "BLOCKED") {
            decisionBadge = `<span class="badge" style="background:var(--rose-bg); color:var(--rose-accent);">BLOCK</span>`;
        } else {
            decisionBadge = `<span class="badge badge-neutral">${log.decision}</span>`;
        }

        tr.innerHTML = `
            <td style="color:var(--text-muted); font-size:11px; white-space:nowrap;">${log.timestamp}</td>
            <td><code class="mono">${log.src_ip}</code></td>
            <td><code class="mono">${log.dst_ip}</code></td>
            <td><strong>${log.protocol}</strong></td>
            <td><code class="mono">${log.port}</code></td>
            <td>${decisionBadge}</td>
            <td>
                <div style="font-size:12px; color:var(--text-primary);">${log.reason}</div>
                ${log.path && log.path !== "-" ? `<div style="font-size:11px; color:var(--cyan-glow); font-family:var(--font-mono); margin-top:2px;">Path: ${log.path}</div>` : ""}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function confirmClearLogs() {
    document.getElementById("clear-confirm-modal").classList.remove("hidden");
}

function closeModal() {
    document.getElementById("clear-confirm-modal").classList.add("hidden");
}

async function executeClearLogs() {
    closeModal();
    try {
        const response = await fetch("/api/logs", { method: "DELETE" });
        if (!response.ok) throw new Error("Failed to clear logs");

        showToast("Activity logs cleared.", "info");
        fetchLogs();
    } catch (err) {
        console.error("Error clearing logs:", err);
        showToast("Failed to clear logs.", "error");
    }
}

// -------------------------------------------------------------
// Toast Notifications System
// -------------------------------------------------------------
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;

    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "error") icon = "⚠️";

    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(100%)";
        toast.style.transition = "all 0.3s ease-out";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}
