# PrintGuard Bridge

A small LAN-friendly bridge for **PrintGuard** that:

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
