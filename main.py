from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import os
import secrets

import scanner.discovery as discovery
from scanner.activity import start_dns_monitor
from database.database import get_connection, initialize_database


# ============================================================
# CONFIGURATION & STARTUP
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

try:
    initialize_database()
except Exception as exc:
    print(f"[NEXUS] Database initialization deferred: {exc}")

if os.getenv("VERCEL") != "1":
    try:
        start_dns_monitor()
    except Exception as exc:
        print(f"[NEXUS] DNS monitor not started: {exc}")


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="NEXUS - Network Asset Intelligence",
    version="1.0"
)


# ============================================================
# STATIC FRONTEND
# ============================================================

app.mount(
    "/static",
    StaticFiles(
        directory=FRONTEND_DIR
    ),
    name="static"
)


# ============================================================
# AUTHORIZATION TOKENS
# ============================================================

authorization_tokens = {}


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
@app.get("/index.html")
def home():

    return FileResponse(
        os.path.join(FRONTEND_DIR, "index.html")
    )


@app.get("/favicon.ico")
def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


# ============================================================
# GET CURRENT NETWORKS
# ============================================================

@app.get("/api/network")
def get_network():

    try:

        networks = discovery.get_networks()

        return {
            "success": True,
            "networks": networks
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error)
        }


# ============================================================
# AUTHORIZE NETWORK
# ============================================================

@app.post("/api/authorize")
def authorize_network(
    data: dict
):

    try:

        requested_networks = (
            data.get(
                "networks",
                []
            )
        )


        current_networks = (
            discovery.get_networks()
        )


        current_names = {
            item["network"]
            for item in current_networks
        }


        requested_names = {
            item.get("network")
            for item in requested_networks
            if item.get("network")
        }


        if not requested_names:

            return {
                "success": False,
                "message":
                    "No networks supplied."
            }


        if not requested_names.issubset(
            current_names
        ):

            return {
                "success": False,
                "message":
                    "One or more networks "
                    "are no longer available."
            }


        token = secrets.token_urlsafe(
            32
        )


        authorization_tokens[token] = {
            "networks":
                list(requested_names)
        }


        return {
            "success": True,

            "token":
                token,

            "networks":
                list(requested_names)
        }


    except Exception as error:

        return {
            "success": False,
            "message": str(error)
        }


# ============================================================
# GET DEVICES
# ============================================================

@app.get("/api/devices")
def get_devices():

    connection = get_connection()
    rows = connection.execute(
        """
        SELECT
            id,
            ip_address,
            mac_address,
            hostname,
            network,
            interface,
            first_seen,
            last_seen,
            status,
            open_ports,
            missed_scans
        FROM devices
        ORDER BY id
        """
    ).fetchall()
    devices = []
    for row in rows:
        services = []
        for item in (row[9] or "None").split(","):
            item = item.strip()
            if not item or item == "None" or ":" not in item:
                continue
            port, service = item.split(":", 1)
            services.append({"port": port, "service": service})
        devices.append({
            "id": row[0], "ip_address": row[1], "mac_address": row[2],
            "hostname": row[3] or "Unknown", "network": row[4] or "Unknown",
            "interface": row[5] or "Unknown", "first_seen": row[6],
            "last_seen": row[7], "status": row[8], "open_ports": row[9] or "None",
            "services": services, "missed_scans": row[10] or 0
        })
    connection.close()
    return devices


@app.get("/api/devices/{device_id}/activity")
def get_device_activity(device_id: int, limit: int = 30):
    connection = get_connection()
    device = connection.execute(
        "SELECT id, mac_address, ip_address, first_seen FROM devices WHERE id = ?",
        (device_id,)
    ).fetchone()

    if not device:
        connection.close()
        return []

    rows = connection.execute(
        """
        SELECT event_type, message, ip_address, created_at
        FROM device_activity
        WHERE device_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (device_id, max(1, min(limit, 100)))
    ).fetchall()

    events = [
        {
            "event_type": row[0],
            "message": row[1],
            "ip_address": row[2],
            "created_at": row[3]
        }
        for row in rows
    ]

    # Older devices predate the activity table, so include their existing
    # alert history until new scans have produced native activity events.
    alert_rows = connection.execute(
        """
        SELECT alert_type, message, ip_address, created_at
        FROM alerts
        WHERE ip_address = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (device[2], max(1, min(limit, 100)))
    ).fetchall()
    events.extend(
        {
            "event_type": row[0],
            "message": row[1],
            "ip_address": row[2],
            "created_at": row[3]
        }
        for row in alert_rows
    )

    if not events:
        events.append({
            "event_type": "DEVICE_HISTORY",
            "message": "Device history begins with the next discovery scan.",
            "ip_address": device[2],
            "created_at": device[3]
        })

    events.sort(key=lambda event: event["created_at"] or "", reverse=True)
    connection.close()
    return events[:max(1, min(limit, 100))]


# ============================================================
# GET ALERTS
# ============================================================

@app.get("/api/alerts")
def get_alerts():

    connection = get_connection()
    rows = connection.execute(
        """
        SELECT
            id,
            alert_type,
            message,
            ip_address,
            created_at,
            acknowledged
        FROM alerts
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    connection.close()
    return [
        {"id": row[0], "alert_type": row[1], "message": row[2],
         "ip_address": row[3], "created_at": row[4], "acknowledged": row[5]}
        for row in rows
    ]


@app.post("/api/clear-data")
def clear_data(data: dict):
    token = data.get("token")
    if not token or token not in authorization_tokens:
        return {
            "success": False,
            "message": "Authorization required to clear monitoring data."
        }

    connection = get_connection()
    connection.execute("DELETE FROM device_activity")
    connection.execute("DELETE FROM network_activity")
    connection.execute("DELETE FROM alerts")
    connection.execute("DELETE FROM devices")
    connection.execute(
        "UPDATE scan_meta SET last_scan = NULL, networks = '' WHERE id = 1"
    )
    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "Monitoring data cleared."
    }


@app.get("/api/network-activity")
def get_network_activity(limit: int = 100):
    connection = get_connection()
    rows = connection.execute(
        """
        SELECT ip_address, domain, category, created_at
        FROM network_activity
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, min(limit, 500)),)
    ).fetchall()
    connection.close()
    return [
        {
            "ip_address": row[0],
            "domain": row[1],
            "category": row[2],
            "created_at": row[3]
        }
        for row in rows
    ]


# ============================================================
# GET SCAN INFORMATION
# ============================================================

@app.get("/api/scan-info")
def get_scan_info():

    connection = get_connection()
    row = connection.execute(
        """
        SELECT
            last_scan,
            networks
        FROM scan_meta
        WHERE id = 1
        """
    ).fetchone()
    connection.close()


    if not row:

        return {
            "last_scan": None,
            "networks": []
        }


    networks = []


    if row[1]:

        networks = [
            item.strip()
            for item in row[1].split(",")
            if item.strip()
        ]


    return {
        "last_scan":
            row[0],

        "networks":
            networks
    }


# ============================================================
# RUN NETWORK DISCOVERY
# ============================================================

@app.post("/api/scan")
def run_scan(
    data: dict
):

    token = data.get(
        "token"
    )


    # --------------------------------------------------------
    # CHECK TOKEN
    # --------------------------------------------------------

    if not token:

        return {
            "success": False,
            "message":
                "Authorization token required."
        }


    # --------------------------------------------------------
    # CHECK AUTHORIZATION
    # --------------------------------------------------------

    authorization = (
        authorization_tokens.get(
            token
        )
    )


    if not authorization:

        return {
            "success": False,
            "message":
                "Authorization expired "
                "or invalid."
        }


    try:

        # ----------------------------------------------------
        # CHECK CURRENT NETWORK
        # ----------------------------------------------------

        current_networks = (
            discovery.get_networks()
        )


        current_names = {
            item["network"]
            for item in current_networks
        }


        authorized_names = set(
            authorization["networks"]
        )


        # ----------------------------------------------------
        # NETWORK CHANGED
        # ----------------------------------------------------

        if not authorized_names.issubset(
            current_names
        ):

            authorization_tokens.pop(
                token,
                None
            )


            return {
                "success": False,
                "message":
                    "Network changed. "
                    "Authorization required again."
            }


        result = discovery.discover_devices()

        return {
            "success": True,
            "message": "Discovery completed.",
            "result": result
        }


    except Exception as error:

        return {

            "success":
                False,

            "message":
                "Unable to run discovery.",

            "error":
                str(error)
        }