# PrintGuard Bridge

A small LAN-friendly bridge for **PrintGuard** (by /u/oliverbravery https://github.com/oliverbravery/PrintGuard) that:

- Polls PrintGuard’s API (often running locally on the same machine via HTTPS / self-signed cert)
- Exposes a stable HTTP endpoint suitable for **Home Assistant**, **Hubitat**, webhooks, etc.
- Optionally exposes **control endpoints** (pause/cancel/dismiss alerts, start/stop detection) — disabled by default

This project is **not affiliated with PrintGuard**.

## Why this exists

PrintGuard runs locally and may use self-signed TLS. Home automation platforms and other LAN devices often prefer:

- A simple **HTTP** endpoint on the LAN
- A consistent JSON shape for polling (`/health`, `/alerts`)
- A place to centralize TLS verification rules, timeouts, and retries

This bridge does exactly that.

---

## Features

### Read-only (default)
- `GET /health` — status, timestamps, last error, config
- `GET /alerts` — current active alerts (cached from PrintGuard)

### Optional control (disabled by default)
When enabled, adds:
- `POST /alert/action` — dismiss / pause_print / cancel_print
- `POST /detection/start` — start live detection for multiple cameras
- `POST /detection/stop` — stop live detection for multiple cameras

Control endpoints require:
- `ENABLE_CONTROL=1`
- `BRIDGE_AUTH_TOKEN` (sent by clients as `X-Auth-Token`)

---

## Requirements

- Python 3.10+ recommended
- Dependencies:
  - `Flask`
  - `requests`

Example `requirements.txt`:

```txt
Flask>=2.3
requests>=2.31


**Quick start**

1) Create a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

2) Install dependencies
pip install -r requirements.txt

3) Run the bridge

By default it assumes PrintGuard is at https://127.0.0.1:8000 and does not verify TLS (common for self-signed local certs).

python printguard_bridge.py


You should see logs like:

Monitoring alerts from https://127.0.0.1:8000

Bridge listening on http://0.0.0.0:8055

Configuration

Configuration can be supplied via CLI args or environment variables.

Common environment variables
Variable	Default	Meaning
PRINTGUARD_URL	https://127.0.0.1:8000	PrintGuard base URL
PRINTGUARD_VERIFY_SSL	0	Verify PrintGuard TLS certificate
POLL_INTERVAL_SEC	2	How often to poll /alert/active
BRIDGE_BIND_HOST	0.0.0.0	Interface to bind
BRIDGE_PORT	8055	Port to bind
PG_CONNECT_TIMEOUT_SEC	3	HTTP connect timeout
PG_READ_TIMEOUT_SEC	10	HTTP read timeout
ENABLE_CONTROL	0	Enable mutating endpoints
BRIDGE_AUTH_TOKEN	(empty)	Required token for control endpoints

Example:

set PRINTGUARD_URL=https://127.0.0.1:8000
set POLL_INTERVAL_SEC=2
set PRINTGUARD_VERIFY_SSL=0
python printguard_bridge.py

API
GET /health

Example response:

{
  "ok": true,
  "ts_utc": "...",
  "version": "1.0.0",
  "poll_interval_sec": 2,
  "printguard_base_url": "https://127.0.0.1:8000",
  "printguard_verify_ssl": false,
  "control_enabled": false,
  "cache": {
    "last_poll_utc": "...",
    "last_ok_utc": "...",
    "last_error": null,
    "active_alerts_count": 0
  }
}

GET /alerts

Example response:

{
  "ok": true,
  "ts_utc": "...",
  "data": {
    "active_alerts": []
  },
  "meta": {
    "cached_from": "https://127.0.0.1:8000",
    "last_poll_utc": "...",
    "last_ok_utc": "...",
    "last_error": null
  }
}

Home Assistant integration (example)

A simple REST sensor that polls the bridge:

rest:
  - resource: "http://<BRIDGE_LAN_IP>:8055/alerts"
    scan_interval: 2
    sensor:
      - name: "PrintGuard Active Alerts Count"
        value_template: "{{ value_json.data.active_alerts | length }}"
        json_attributes_path: "$.data"
        json_attributes:
          - active_alerts


Then a binary sensor:

template:
  - binary_sensor:
      - name: "PrintGuard Alert Active"
        state: "{{ (states('sensor.printguard_active_alerts_count') | int(0)) > 0 }}"


If you enable control endpoints, you can use rest_command with a token header:

rest_command:
  printguard_pause_latest:
    url: "http://<BRIDGE_LAN_IP>:8055/alert/action"
    method: POST
    headers:
      Content-Type: application/json
      X-Auth-Token: !secret printguard_bridge_token
    payload: >
      {"alert_id":"{{ states('sensor.printguard_latest_alert_id') }}","action":"pause_print"}
