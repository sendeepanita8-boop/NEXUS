let networks = [];
let devices = [];
let alerts = [];

let authorizationToken = null;
let monitoringStarted = false;
let monitoringTimer = null;


/* =====================================================
   HELPER
===================================================== */

function $(id) {
    return document.getElementById(id);
}


/* =====================================================
   START APPLICATION
===================================================== */

window.addEventListener("DOMContentLoaded", function () {

    console.log("NEXUS: Application started");

    setupEvents();

    refreshDashboard();

});


/* =====================================================
   SAFE EVENT LISTENER
===================================================== */

function on(id, event, callback) {

    const element = $(id);

    if (!element) {
        console.warn("NEXUS: Missing element:", id);
        return;
    }

    element.addEventListener(event, callback);
}


/* =====================================================
   EVENTS
===================================================== */

function setupEvents() {

    on("authorizeBtn", "click", openPermissionModal);

    on("clearDataBtn", "click", clearMonitoringData);

    on("closePermission", "click", closePermissionModal);

    on("cancelPermission", "click", closePermissionModal);

    on("confirmPermission", "click", authorizeAndScan);

    on("permissionCheckbox", "change", updatePermissionButton);

    on("scanBtn", "click", startScan);

    on("refreshBtn", "click", refreshDashboard);

    on("searchInput", "input", renderDevices);

    on("statusFilter", "change", renderDevices);

    on("closeDevice", "click", closeDeviceModal);


    on("permissionModal", "click", function (event) {

        if (event.target === $("permissionModal")) {
            closePermissionModal();
        }

    });


    on("deviceModal", "click", function (event) {

        if (event.target === $("deviceModal")) {
            closeDeviceModal();
        }

    });

}


async function clearMonitoringData() {

    if (!authorizationToken) {
        alert("Authorize a network before clearing monitoring data.");
        return;
    }

    if (!window.confirm("Clear all devices, alerts, activity history, and scan data?")) {
        return;
    }

    const button = $("clearDataBtn");
    if (button) {
        button.disabled = true;
        button.textContent = "CLEARING...";
    }

    try {
        const response = await fetch("/api/clear-data", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token: authorizationToken })
        });
        const data = await response.json();

        if (!data.success) {
            throw new Error(data.message || "Unable to clear monitoring data.");
        }

        devices = [];
        alerts = [];
        renderDevices();
        renderAlerts();
        await loadNetworkActivity();
        await loadScanInfo();
        updateStats();
    } catch (error) {
        console.error("NEXUS CLEAR DATA ERROR:", error);
        alert(error.message);
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "CLEAR DATA";
        }
    }
}


/* =====================================================
   LOAD NETWORK
===================================================== */

async function loadNetwork() {

    setNetworkStatus("DETECTING...");

    try {

        const response = await fetch("/api/network", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(
                "Network API returned HTTP " + response.status
            );
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(
                data.error || "Network detection failed"
            );
        }

        networks = Array.isArray(data.networks)
            ? data.networks
            : [];

        renderNetworks();

        if (networks.length > 0) {
            setNetworkStatus("NETWORKS DETECTED");
        } else {
            setNetworkStatus("NO PRIVATE NETWORK");
        }

    } catch (error) {

        console.error("NEXUS NETWORK ERROR:", error);

        networks = [];

        if ($("networkCount")) {
            $("networkCount").textContent = "0";
        }

        if ($("networkDescription")) {
            $("networkDescription").textContent =
                "Unable to detect local networks.";
        }

        if ($("networkList")) {

            $("networkList").innerHTML = `
                <div class="empty-state">
                    Network detection failed.
                </div>
            `;

        }

        setNetworkStatus("DETECTION FAILED");
    }

}


/* =====================================================
   NETWORK STATUS
===================================================== */

function setNetworkStatus(status) {

    const element = $("networkStatus");

    if (element) {
        element.textContent = status;
    }

}


/* =====================================================
   RENDER NETWORKS
===================================================== */

function renderNetworks() {

    const count = $("networkCount");
    const description = $("networkDescription");
    const list = $("networkList");

    if (!count || !description || !list) {
        console.warn("NEXUS: Network UI elements missing.");
        return;
    }

    count.textContent = networks.length;

    if (!networks.length) {

        description.textContent =
            "No reachable private IPv4 networks detected.";

        list.innerHTML = `
            <div class="empty-state">
                No private networks detected.
            </div>
        `;

        return;
    }

    description.textContent =
        "Private IPv4 networks available for authorized discovery.";

    list.innerHTML = networks.map(function (network) {

        return `
            <div class="network-item">

                <div class="network-title">
                    ${escapeHTML(network.network)}
                </div>

                <div class="network-info">

                    <div>
                        <span>LOCAL IP</span>
                        <strong>
                            ${escapeHTML(network.local_ip)}
                        </strong>
                    </div>

                    <div>
                        <span>GATEWAY</span>
                        <strong>
                            ${escapeHTML(network.gateway)}
                        </strong>
                    </div>

                    <div>
                        <span>SUBNET</span>
                        <strong>
                            ${escapeHTML(network.subnet_mask)}
                        </strong>
                    </div>

                    <div>
                        <span>INTERFACE</span>
                        <strong>
                            ${escapeHTML(network.interface)}
                        </strong>
                    </div>

                </div>

            </div>
        `;

    }).join("");

}


/* =====================================================
   PERMISSION MODAL
===================================================== */

function openPermissionModal() {

    renderPermissionNetworks();

    if ($("permissionCheckbox")) {
        $("permissionCheckbox").checked = false;
    }

    updatePermissionButton();

    if ($("permissionModal")) {
        $("permissionModal").classList.add("active");
    }

}


function closePermissionModal() {

    if ($("permissionModal")) {
        $("permissionModal").classList.remove("active");
    }

}


function renderPermissionNetworks() {

    const container = $("permissionNetworks");

    if (!container) {
        return;
    }

    if (!networks.length) {

        container.innerHTML = `
            <div class="empty-state">
                No networks detected.
            </div>
        `;

        return;
    }

    container.innerHTML = networks.map(function (network) {

        return `
            <div class="permission-network">

                <strong>
                    ${escapeHTML(network.network)}
                </strong>

                <span>
                    IP:
                    ${escapeHTML(network.local_ip)}

                    &nbsp; • &nbsp;

                    Gateway:
                    ${escapeHTML(network.gateway)}

                    &nbsp; • &nbsp;

                    Interface:
                    ${escapeHTML(network.interface)}
                </span>

            </div>
        `;

    }).join("");

}


function updatePermissionButton() {

    const checkbox = $("permissionCheckbox");
    const button = $("confirmPermission");

    if (!checkbox || !button) {
        return;
    }

    button.disabled = !checkbox.checked;

    button.style.opacity =
        checkbox.checked ? "1" : "0.45";

}


/* =====================================================
   AUTHORIZE
===================================================== */

async function authorizeAndScan() {

    if (
        !$("permissionCheckbox") ||
        !$("permissionCheckbox").checked
    ) {
        return;
    }

    const button = $("confirmPermission");

    if (button) {

        button.disabled = true;
        button.textContent = "AUTHORIZING...";

    }

    try {

        const response = await fetch("/api/authorize", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                networks: networks
            })

        });

        const data = await response.json();

        if (!data.success) {

            throw new Error(
                data.message || "Authorization failed"
            );

        }

        authorizationToken = data.token;

        closePermissionModal();

        await startScan();

        startMonitoring();

    } catch (error) {

        console.error(
            "NEXUS AUTHORIZATION ERROR:",
            error
        );

        alert(
            "Authorization failed:\n\n" +
            error.message
        );

    } finally {

        if (button) {

            button.disabled = false;
            button.textContent = "AUTHORIZE & CONTINUE";

        }

        updatePermissionButton();

    }

}


/* =====================================================
   START SCAN
===================================================== */

async function startScan() {

    if (!authorizationToken) {

        openPermissionModal();
        return;

    }

    const button = $("scanBtn");

    if (button) {

        button.disabled = true;
        button.textContent = "SCANNING...";

    }

    setNetworkStatus("DISCOVERY RUNNING");

    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                token: authorizationToken
            })

        });

        const data = await response.json();

        if (!data.success) {

            const message =
                data.message ||
                data.error ||
                "Discovery failed";

            if (
                message
                    .toLowerCase()
                    .includes("network changed")
            ) {

                authorizationToken = null;

                setNetworkStatus(
                    "AUTHORIZATION REQUIRED"
                );

                alert(
                    "The network changed.\n\n" +
                    "Please authorize the current network again."
                );

                await loadNetwork();

                openPermissionModal();

                return;
            }

            throw new Error(message);
        }

        await loadDevices();
        await loadAlerts();
        await loadScanInfo();

        setNetworkStatus("DISCOVERY COMPLETE");

    } catch (error) {

        console.error(
            "NEXUS SCAN ERROR:",
            error
        );

        alert(
            "Discovery failed:\n\n" +
            error.message
        );

        setNetworkStatus("DISCOVERY ERROR");

    } finally {

        if (button) {

            button.disabled = false;
            button.textContent = "START DISCOVERY";

        }

    }

}


/* =====================================================
   LOAD DEVICES
===================================================== */

async function loadDevices() {

    try {

        const response = await fetch("/api/devices", {
            cache: "no-store"
        });

        if (!response.ok) {

            throw new Error(
                "Device API returned HTTP " +
                response.status
            );

        }

        devices = await response.json();

        if (!Array.isArray(devices)) {
            devices = [];
        }

        renderDevices();
        updateStats();

    } catch (error) {

        console.error(
            "NEXUS DEVICE ERROR:",
            error
        );

    }

}


async function loadDeviceActivity(deviceId) {

    try {
        const response = await fetch(
            `/api/devices/${encodeURIComponent(deviceId)}/activity?limit=30`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("Activity API returned HTTP " + response.status);
        }

        const activity = await response.json();
        const container = $("deviceActivity");

        if (!container) {
            return;
        }

        container.innerHTML = Array.isArray(activity) && activity.length
            ? activity.map(function (event) {
                return `
                    <div class="activity-item">
                        <div>
                            <strong>${escapeHTML(event.event_type)}</strong>
                            <span>${escapeHTML(event.message)}</span>
                        </div>
                        <time>${formatDate(event.created_at)}</time>
                    </div>
                `;
            }).join("")
            : '<div class="empty-state">No activity recorded yet.</div>';
    } catch (error) {
        console.error("NEXUS ACTIVITY ERROR:", error);
        const container = $("deviceActivity");
        if (container) {
            container.innerHTML = '<div class="empty-state">Activity history unavailable.</div>';
        }
    }
}


/* =====================================================
   RENDER DEVICES
===================================================== */

function renderDevices() {

    const table = $("deviceTable");

    if (!table) {
        return;
    }

    const searchElement = $("searchInput");
    const filterElement = $("statusFilter");

    const search = searchElement
        ? searchElement.value.trim().toLowerCase()
        : "";

    const filter = filterElement
        ? filterElement.value
        : "ALL";

    const filtered = devices.filter(function (device) {

        const ip = String(
            device.ip_address || ""
        ).toLowerCase();

        const hostname = String(
            device.hostname || ""
        ).toLowerCase();

        const mac = String(
            device.mac_address || ""
        ).toLowerCase();

        const matchesSearch =
            !search ||
            ip.includes(search) ||
            hostname.includes(search) ||
            mac.includes(search);

        const matchesStatus =
            filter === "ALL" ||
            device.status === filter;

        return matchesSearch && matchesStatus;

    });


    if ($("assetCountLabel")) {

        $("assetCountLabel").textContent =
            filtered.length + " ASSETS";

    }


    if (!filtered.length) {

        table.innerHTML = `
            <tr>
                <td colspan="6" class="empty-table">
                    No devices discovered yet.
                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML = filtered.map(function (device) {

        const status = String(
            device.status || "OFFLINE"
        ).toUpperCase();

        return `
            <tr
                class="device-row"
                data-id="${escapeHTML(device.id)}"
            >

                <td>

                    <span class="status ${
                        status === "ONLINE"
                            ? "online"
                            : "offline"
                    }">

                        ${escapeHTML(status)}

                    </span>

                </td>

                <td class="ip">
                    ${escapeHTML(device.ip_address)}
                </td>

                <td class="hostname">
                    ${escapeHTML(
                        device.hostname || "Unknown"
                    )}
                </td>

                <td class="mac">
                    ${escapeHTML(device.mac_address)}
                </td>

                <td class="ports">
                    ${formatPorts(device.open_ports)}
                </td>

                <td class="last-seen">
                    ${formatDate(device.last_seen)}
                </td>

            </tr>
        `;

    }).join("");


    document
        .querySelectorAll(".device-row")
        .forEach(function (row) {

            row.addEventListener("click", function () {

                const id = Number(row.dataset.id);

                const device = devices.find(
                    function (item) {
                        return Number(item.id) === id;
                    }
                );

                if (device) {
                    openDeviceModal(device);
                }

            });

        });

}


/* =====================================================
   STATISTICS
===================================================== */

function updateStats() {

    const total = devices.length;

    const online = devices.filter(function (device) {

        return device.status === "ONLINE";

    }).length;

    const offline = devices.filter(function (device) {

        return device.status === "OFFLINE";

    }).length;


    if ($("totalAssets")) {
        $("totalAssets").textContent = total;
    }

    if ($("onlineAssets")) {
        $("onlineAssets").textContent = online;
    }

    if ($("offlineAssets")) {
        $("offlineAssets").textContent = offline;
    }

    if ($("alertCount")) {
        $("alertCount").textContent = alerts.length;
    }

}


/* =====================================================
   ALERTS
===================================================== */

async function loadAlerts() {

    try {

        const response = await fetch("/api/alerts", {
            cache: "no-store"
        });

        if (!response.ok) {

            throw new Error(
                "Alert API returned HTTP " +
                response.status
            );

        }

        alerts = await response.json();

        if (!Array.isArray(alerts)) {
            alerts = [];
        }

        renderAlerts();
        updateStats();

    } catch (error) {

        console.error(
            "NEXUS ALERT ERROR:",
            error
        );

    }

}


async function loadNetworkActivity() {

    const container = $("networkActivityList");
    if (!container) {
        return;
    }

    try {
        const response = await fetch("/api/network-activity?limit=100", {
            cache: "no-store"
        });
        if (!response.ok) {
            throw new Error("Network activity API returned HTTP " + response.status);
        }

        const activity = await response.json();
        if (!Array.isArray(activity) || !activity.length) {
            container.innerHTML = '<div class="empty-state">No visible DNS activity yet.</div>';
            return;
        }

        container.innerHTML = activity.map(function (event) {
            return `
                <div class="network-activity-item">
                    <span class="activity-category">${escapeHTML(event.category)}</span>
                    <strong>${escapeHTML(event.domain)}</strong>
                    <span class="activity-device">${escapeHTML(event.ip_address)}</span>
                    <time>${formatDate(event.created_at)}</time>
                </div>
            `;
        }).join("");
    } catch (error) {
        console.error("NEXUS NETWORK ACTIVITY ERROR:", error);
        container.innerHTML = '<div class="empty-state">Network activity monitor unavailable.</div>';
    }
}


function renderAlerts() {

    const container = $("alertsList");

    if (!container) {
        return;
    }

    if (!alerts.length) {

        container.innerHTML = `
            <div class="empty-state">
                No security events recorded.
            </div>
        `;

        return;
    }

    container.innerHTML = alerts.map(function (alert) {

        return `
            <div class="alert">

                <div class="alert-type">
                    ${escapeHTML(alert.alert_type)}
                </div>

                <div class="alert-message">
                    ${escapeHTML(alert.message)}
                </div>

                <div class="alert-time">
                    ${formatDate(alert.created_at)}
                </div>

            </div>
        `;

    }).join("");

}


/* =====================================================
   SCAN INFO
===================================================== */

async function loadScanInfo() {

    try {

        const response = await fetch("/api/scan-info", {
            cache: "no-store"
        });

        if (!response.ok) {
            return;
        }

        const data = await response.json();

        if (data.last_scan && $("lastScan")) {

            $("lastScan").textContent =
                "Last scan: " +
                formatDate(data.last_scan);

        }

    } catch (error) {

        console.error(
            "NEXUS SCAN INFO ERROR:",
            error
        );

    }

}


/* =====================================================
   MONITORING
===================================================== */

function startMonitoring() {

    if (monitoringStarted) {
        return;
    }

    monitoringStarted = true;

    if ($("monitorText")) {

        $("monitorText").textContent =
            "MONITORING ACTIVE";

    }

    monitoringTimer = setInterval(
        function () {

            if (authorizationToken) {
                backgroundScan();
            }

        },
        60000
    );

}


async function backgroundScan() {

    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                token: authorizationToken
            })

        });

        const data = await response.json();

        if (!data.success) {

            if (
                String(data.message || "")
                    .toLowerCase()
                    .includes("network changed")
            ) {

                authorizationToken = null;

                if ($("monitorText")) {

                    $("monitorText").textContent =
                        "AUTHORIZATION REQUIRED";

                }

                return;
            }

        }

        await loadDevices();
        await loadAlerts();
        await loadNetworkActivity();
        await loadScanInfo();

    } catch (error) {

        console.error(
            "NEXUS MONITORING ERROR:",
            error
        );

    }

}


/* =====================================================
   DEVICE DETAILS
===================================================== */

function openDeviceModal(device) {

    const title = $("deviceModalTitle");
    const details = $("deviceDetails");
    const modal = $("deviceModal");

    if (!title || !details || !modal) {
        return;
    }

    title.textContent =
        device.hostname &&
        device.hostname !== "Unknown"
            ? device.hostname
            : device.ip_address;


    details.innerHTML = `

        <div class="detail-box">
            <div class="detail-label">STATUS</div>
            <div class="detail-value">
                ${escapeHTML(device.status)}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">IP ADDRESS</div>
            <div class="detail-value">
                ${escapeHTML(device.ip_address)}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">MAC ADDRESS</div>
            <div class="detail-value">
                ${escapeHTML(device.mac_address)}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">HOSTNAME</div>
            <div class="detail-value">
                ${escapeHTML(
                    device.hostname || "Unknown"
                )}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">NETWORK</div>
            <div class="detail-value">
                ${escapeHTML(
                    device.network || "Unknown"
                )}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">INTERFACE</div>
            <div class="detail-value">
                ${escapeHTML(
                    device.interface || "Unknown"
                )}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">OPEN PORTS</div>
            <div class="detail-value">
                ${device.services && device.services.length
                    ? device.services.map(function (service) {
                        return `<span class="service-chip">${escapeHTML(service.port)} / ${escapeHTML(service.service)}</span>`;
                    }).join("")
                    : "None observed"}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">MISSED SCANS</div>
            <div class="detail-value">
                ${escapeHTML(
                    String(device.missed_scans || 0)
                )}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">FIRST SEEN</div>
            <div class="detail-value">
                ${formatDate(device.first_seen)}
            </div>
        </div>

        <div class="detail-box">
            <div class="detail-label">LAST SEEN</div>
            <div class="detail-value">
                ${formatDate(device.last_seen)}
            </div>
        </div>

        <div class="device-section-heading">OBSERVED ACTIVITY</div>
        <div id="deviceActivity" class="device-activity">
            <div class="empty-state">Loading activity...</div>
        </div>

    `;

    modal.classList.add("active");
    loadDeviceActivity(device.id);

}


function closeDeviceModal() {

    if ($("deviceModal")) {

        $("deviceModal")
            .classList
            .remove("active");

    }

}


/* =====================================================
   REFRESH
===================================================== */

async function refreshDashboard() {

    const button = $("refreshBtn");

    if (button) {

        button.disabled = true;
        button.textContent = "REFRESHING...";

    }

    try {

        await loadNetwork();
        await loadDevices();
        await loadAlerts();
        await loadNetworkActivity();
        await loadScanInfo();

    } finally {

        if (button) {

            button.disabled = false;
            button.textContent = "REFRESH";

        }

    }

}


/* =====================================================
   FORMATTERS
===================================================== */

function formatPorts(value) {

    if (!value || value === "None") {
        return "None";
    }

    return escapeHTML(value).replace(
        /, /g,
        "<br>"
    );

}


function formatDate(value) {

    if (!value) {
        return "—";
    }

    try {

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {

            return escapeHTML(value);

        }

        return escapeHTML(
            date.toLocaleString()
        );

    } catch {

        return escapeHTML(value);

    }

}


/* =====================================================
   SECURITY
===================================================== */

function escapeHTML(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}

window.startScan = startScan;
window.refreshDashboard = refreshDashboard;
window.openPermissionModal = openPermissionModal;
window.closePermissionModal = closePermissionModal;
window.authorizeAndScan = authorizeAndScan;
window.showDevice = openDeviceModal;
window.closeDeviceModal = closeDeviceModal;