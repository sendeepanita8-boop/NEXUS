# NEXUS Network Asset Intelligence

![NEXUS dashboard overview](assets/nexus-overview.svg)

NEXUS is a network asset monitor for private IPv4 networks you own or are authorized to monitor. Its Windows scanner discovers responding devices, checks common TCP ports, records device and alert history, and captures DNS queries visible to the host. A FastAPI backend serves the dashboard and stores records in PostgreSQL.

> Use NEXUS only on networks and devices you own or are explicitly authorized to monitor.

## Features

- Detects private networks configured on Windows and discovers responding devices with ARP.
- Resolves hostnames when available and checks common TCP ports for likely services.
- Tracks new, online, offline, and port-change events, with per-device activity history.
- Records visible DNS queries and groups domains into categories including video, social, messaging, gaming, productivity, and shopping.
- Shows devices, alerts, scan information, and recent DNS activity in a responsive dashboard.
- Supports clearing stored monitoring data from the dashboard.

## Requirements

- Windows 10 or later for the scanner
- Python 3.10 or later
- A PostgreSQL database reachable from the app (for example, Neon or a Vercel Postgres integration)
- Npcap in WinPcap-compatible mode for Scapy packet capture and ARP discovery
- Permission to scan the selected private networks

NEXUS does not inspect message content, passwords, page contents, private conversations, or exact in-app actions. HTTPS and encrypted DNS limit what DNS monitoring can reveal. DNS activity is visible only when the traffic can be observed by the computer running NEXUS or by a configured gateway.

## Local Setup

In PowerShell, create an environment, install the dependencies, and configure a PostgreSQL connection string:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require"
```

Install [Npcap](https://npcap.com/) with WinPcap API-compatible mode enabled. The database schema is created automatically when the app starts. `DATABASE_URL` is used when set; `POSTGRES_URL` is also accepted for Vercel Postgres integrations.

## Run Locally

Start the API and dashboard:

```powershell
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). To access it from another device on the same network, bind to all interfaces:

```powershell
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8001
```

Then open `http://YOUR-COMPUTER-IP:8001` from that device. Windows Firewall may need to allow Python on the private network.

## Workflow

1. Open the dashboard.
2. Select **AUTHORIZE NETWORK** and confirm you have permission to monitor the listed networks.
3. Start discovery.
4. Select a device to view observed services and activity history.
5. Review **Recent Connections** and **Recent Alerts**.
6. Use **CLEAR DATA** to remove stored monitoring records.

## API Overview

| Endpoint | Purpose |
| --- | --- |
| `GET /api/network` | Detect networks on the scanner host |
| `POST /api/authorize` | Authorize selected networks for scanning |
| `GET /api/devices` | List discovered devices and observed services |
| `GET /api/devices/{device_id}/activity` | Read activity history for a device |
| `GET /api/alerts` | List recent alerts |
| `GET /api/network-activity` | List timestamped DNS activity |
| `GET /api/scan-info` | Read the last scan time and networks |
| `POST /api/scan` | Run an authorized discovery scan |
| `POST /api/clear-data` | Delete stored monitoring data |

## Vercel Deployment

Vercel can host the FastAPI dashboard and PostgreSQL-backed API. Vercel recognizes `main.py` as the FastAPI entrypoint and installs the packages in `requirements.txt`.

1. Create a Vercel project from this repository, or install and sign in to the Vercel CLI.
2. Add a PostgreSQL integration to the Vercel project. Confirm that `POSTGRES_URL` (or `DATABASE_URL`) is available in both Preview and Production environments.
3. Deploy from the project root. With the CLI, run `npx vercel` for a Preview deployment and `npx vercel --prod` for Production.

The database schema is initialized automatically when the function starts. `.gitignore` and `.vercelignore` exclude local environments, generated files, environment files, and the local SQLite database from source control and deployment uploads. Do not put database credentials in project files.

Vercel is not a supported host for the scanner. Network detection reads Windows `ipconfig` output, discovery requires local ARP access, and DNS capture uses Scapy/Npcap. Those functions need to run on the authorized local network, typically on the Windows machine. Authorization tokens are stored in process memory and are not shared across serverless instances, so scan authorization is not reliable on Vercel.

The app does not provide user login or access control for its device, alert, and activity endpoints. Do not expose monitoring data publicly; use a private deployment or add an authentication layer before sharing it.

## Project Structure

```text
network-asset-monitor/
├── .gitignore               # Local secrets, database, and generated files
├── .vercelignore            # Files excluded from Vercel deployment uploads
├── assets/
│   └── nexus-overview.svg   # README project image
├── database/
│   └── database.py          # PostgreSQL connection and schema initialization
├── frontend/
│   ├── app.js               # Dashboard behavior and API requests
│   ├── index.html           # Dashboard markup
│   └── style.css            # Dashboard styles
├── scanner/
│   ├── activity.py          # Visible DNS activity capture
│   └── discovery.py         # Network, device, and service discovery
├── main.py                  # FastAPI application and routes
├── requirements.txt         # Runtime dependencies
└── README.md                # Project documentation
```

## Data Storage

Runtime data is stored in PostgreSQL, configured through `DATABASE_URL` or `POSTGRES_URL`. The previous local `network_assets.db` file is not imported automatically. Back up or migrate any records you need before switching to a new database.

## License

No license has been selected yet. Add a license before distributing the project publicly.
