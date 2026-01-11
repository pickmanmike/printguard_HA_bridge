#!/usr/bin/env python3
"""
PrintGuard Bridge (LAN-friendly helper)
--------------------------------------
A small Flask service that:
  - Polls PrintGuard's API (typically local HTTPS w/ self-signed cert)
  - Exposes a stable, LAN-friendly HTTP endpoint for automations (Home Assistant, etc.)
  - Optionally exposes CONTROL endpoints (disabled by default)

Default behavior is READ-ONLY (safe). Control endpoints require ENABLE_CONTROL=1
and a BRIDGE_AUTH_TOKEN.

Not affiliated with PrintGuard.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter

try:
    # urllib3 is a transitive dependency of requests
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore


__version__ = "1.0.0"

DEFAULT_PRINTGUARD_URL = "https://127.0.0.1:8000"
DEFAULT_POLL_INTERVAL_SEC = 2.0
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 8055

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("printguard-bridge")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "y", "on"):
        return True
    if raw in ("0", "false", "no", "n", "off"):
        return False
    return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def build_session() -> requests.Session:
    """Requests session with mild retry behavior (safe for polling)."""
    s = requests.Session()

    if Retry is not None:
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

    return s


@dataclass
class CacheState:
    last_poll_utc: Optional[str] = None
    last_ok_utc: Optional[str] = None
    last_error_utc: Optional[str] = None
    last_error: Optional[str] = None

    # The raw PrintGuard payload from /alert/active
    alert_active_payload: Optional[Dict[str, Any]] = None

    # Convenience view
    active_alerts: List[Dict[str, Any]] = None  # type: ignore

    def __post_init__(self) -> None:
        if self.active_alerts is None:
            self.active_alerts = []


class PrintGuardClient:
    def __init__(
        self,
        base_url: str,
        verify_ssl: bool,
        timeout: Tuple[float, float],
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = session or build_session()

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def get_alert_active(self) -> Dict[str, Any]:
        r = self.session.get(
            self._url("/alert/active"),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            raise ValueError("PrintGuard /alert/active did not return a JSON object")
        # Expected: {"active_alerts":[...]}
        if "active_alerts" not in data or not isinstance(data["active_alerts"], list):
            raise ValueError("PrintGuard /alert/active missing expected 'active_alerts' list")
        return data

    def post_alert_dismiss(self, alert_id: str, action: str) -> Dict[str, Any]:
        payload = {"alert_id": alert_id, "action": action}
        r = self.session.post(
            self._url("/alert/dismiss"),
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            # Some APIs return plain text; wrap it
            return {"ok": True, "raw": r.text}
        return data

    def post_detect_live(self, camera_uuid: str, start: bool) -> Dict[str, Any]:
        path = "/detect/live/start" if start else "/detect/live/stop"
        payload = {"camera_uuid": camera_uuid}
        r = self.session.post(
            self._url(path),
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"ok": True, "raw": r.text}
        return data


def require_auth_if_enabled(enable_control: bool, token: str) -> Optional[Any]:
    """
    If control is enabled, require X-Auth-Token to match BRIDGE_AUTH_TOKEN.
    Returns a Flask response (jsonify) on failure, or None on success.
    """
    if not enable_control:
        return jsonify({"ok": False, "error": "Control endpoints are disabled"}), 403

    if not token:
        return jsonify({"ok": False, "error": "BRIDGE_AUTH_TOKEN is not set on the server"}), 500

    incoming = request.headers.get("X-Auth-Token", "").strip()
    if incoming != token:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    return None


def create_app(
    pg: PrintGuardClient,
    cache: CacheState,
    cache_lock: threading.Lock,
    poll_interval_sec: float,
    enable_control: bool,
    auth_token: str,
) -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health() -> Any:
        with cache_lock:
            snapshot = asdict(cache)
            # Keep payload from being huge
            snapshot["alert_active_payload"] = None
            snapshot["active_alerts_count"] = len(cache.active_alerts)

        return jsonify(
            {
                "ok": True,
                "ts_utc": utc_now_iso(),
                "version": __version__,
                "poll_interval_sec": poll_interval_sec,
                "printguard_base_url": pg.base_url,
                "printguard_verify_ssl": pg.verify_ssl,
                "control_enabled": enable_control,
                "cache": snapshot,
            }
        )

    @app.get("/alerts")
    def alerts() -> Any:
        with cache_lock:
            alerts_list = list(cache.active_alerts)
            last_ok_utc = cache.last_ok_utc
            last_poll_utc = cache.last_poll_utc
            last_error = cache.last_error
            last_error_utc = cache.last_error_utc

        return jsonify(
            {
                "ok": True,
                "ts_utc": utc_now_iso(),
                "data": {"active_alerts": alerts_list},
                "meta": {
                    "cached_from": pg.base_url,
                    "last_poll_utc": last_poll_utc,
                    "last_ok_utc": last_ok_utc,
                    "last_error": last_error,
                    "last_error_utc": last_error_utc,
                },
            }
        )

    # --------------------------
    # Optional CONTROL endpoints
    # --------------------------

    @app.post("/alert/action")
    def alert_action() -> Any:
        denied = require_auth_if_enabled(enable_control, auth_token)
        if denied is not None:
            return denied

        body = request.get_json(silent=True) or {}
        alert_id = str(body.get("alert_id", "")).strip()
        action = str(body.get("action", "")).strip()

        if not alert_id:
            return jsonify({"ok": False, "error": "alert_id is required"}), 400
        if action not in ("dismiss", "pause_print", "cancel_print"):
            return jsonify({"ok": False, "error": "action must be dismiss|pause_print|cancel_print"}), 400

        try:
            data = pg.post_alert_dismiss(alert_id=alert_id, action=action)
            return jsonify({"ok": True, "result": data})
        except Exception as e:
            log.exception("alert_action failed")
            return jsonify({"ok": False, "error": str(e)}), 502

    @app.post("/detection/start")
    def detection_start() -> Any:
        denied = require_auth_if_enabled(enable_control, auth_token)
        if denied is not None:
            return denied

        body = request.get_json(silent=True) or {}
        uuids = body.get("camera_uuids", [])
        if not isinstance(uuids, list) or not all(isinstance(x, str) for x in uuids):
            return jsonify({"ok": False, "error": "camera_uuids must be a list of strings"}), 400

        results = {}
        for cam in uuids:
            cam = cam.strip()
            if not cam:
                continue
            try:
                results[cam] = pg.post_detect_live(camera_uuid=cam, start=True)
            except Exception as e:
                results[cam] = {"ok": False, "error": str(e)}

        return jsonify({"ok": True, "results": results})

    @app.post("/detection/stop")
    def detection_stop() -> Any:
        denied = require_auth_if_enabled(enable_control, auth_token)
        if denied is not None:
            return denied

        body = request.get_json(silent=True) or {}
        uuids = body.get("camera_uuids", [])
        if not isinstance(uuids, list) or not all(isinstance(x, str) for x in uuids):
            return jsonify({"ok": False, "error": "camera_uuids must be a list of strings"}), 400

        results = {}
        for cam in uuids:
            cam = cam.strip()
            if not cam:
                continue
            try:
                results[cam] = pg.post_detect_live(camera_uuid=cam, start=False)
            except Exception as e:
                results[cam] = {"ok": False, "error": str(e)}

        return jsonify({"ok": True, "results": results})

    return app


def poller_thread_fn(
    pg: PrintGuardClient,
    cache: CacheState,
    cache_lock: threading.Lock,
    stop_evt: threading.Event,
    poll_interval_sec: float,
) -> None:
    """
    Poll PrintGuard /alert/active and cache results.
    Never raises out; keeps running until stop_evt is set.
    """
    log.info("Monitoring alerts from %s", pg.base_url)

    while not stop_evt.is_set():
        t0 = time.time()
        try:
            payload = pg.get_alert_active()
            alerts = payload.get("active_alerts", [])

            with cache_lock:
                cache.last_poll_utc = utc_now_iso()
                cache.last_ok_utc = cache.last_poll_utc
                cache.last_error = None
                cache.last_error_utc = None
                cache.alert_active_payload = payload
                # Ensure list of dicts
                cache.active_alerts = [a for a in alerts if isinstance(a, dict)]

        except Exception as e:
            # Don’t kill the bridge; just record the issue.
            with cache_lock:
                cache.last_poll_utc = utc_now_iso()
                cache.last_error_utc = cache.last_poll_utc
                cache.last_error = str(e)
            log.exception("Alert monitor error")

        # Sleep remainder of interval
        elapsed = time.time() - t0
        delay = max(0.0, poll_interval_sec - elapsed)
        stop_evt.wait(delay)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PrintGuard Bridge (LAN-friendly helper)")

    p.add_argument(
        "--printguard-url",
        default=os.environ.get("PRINTGUARD_URL", DEFAULT_PRINTGUARD_URL),
        help=f"PrintGuard base URL (default: {DEFAULT_PRINTGUARD_URL} or env PRINTGUARD_URL)",
    )

    p.add_argument(
        "--verify-ssl",
        action="store_true" if env_bool("PRINTGUARD_VERIFY_SSL", False) else "store_false",
        help="Verify PrintGuard TLS cert (env PRINTGUARD_VERIFY_SSL=1). Default OFF for self-signed.",
    )

    p.add_argument(
        "--poll-interval",
        type=float,
        default=env_float("POLL_INTERVAL_SEC", DEFAULT_POLL_INTERVAL_SEC),
        help=f"Polling interval in seconds (env POLL_INTERVAL_SEC, default {DEFAULT_POLL_INTERVAL_SEC})",
    )

    p.add_argument(
        "--bind-host",
        default=os.environ.get("BRIDGE_BIND_HOST", DEFAULT_BIND_HOST),
        help=f"Bind host/interface (env BRIDGE_BIND_HOST, default {DEFAULT_BIND_HOST})",
    )

    p.add_argument(
        "--bind-port",
        type=int,
        default=env_int("BRIDGE_PORT", DEFAULT_BIND_PORT),
        help=f"Bind port (env BRIDGE_PORT, default {DEFAULT_BIND_PORT})",
    )

    p.add_argument(
        "--connect-timeout",
        type=float,
        default=env_float("PG_CONNECT_TIMEOUT_SEC", 3.0),
        help="Requests connect timeout seconds (env PG_CONNECT_TIMEOUT_SEC, default 3.0)",
    )

    p.add_argument(
        "--read-timeout",
        type=float,
        default=env_float("PG_READ_TIMEOUT_SEC", 10.0),
        help="Requests read timeout seconds (env PG_READ_TIMEOUT_SEC, default 10.0)",
    )

    p.add_argument(
        "--enable-control",
        action="store_true" if env_bool("ENABLE_CONTROL", False) else "store_false",
        help="Enable control endpoints (env ENABLE_CONTROL=1). Default OFF.",
    )

    return p.parse_args()


def main() -> None:
    args = parse_args()

    auth_token = os.environ.get("BRIDGE_AUTH_TOKEN", "").strip()
    if args.enable_control and not auth_token:
        log.warning(
            "ENABLE_CONTROL is ON but BRIDGE_AUTH_TOKEN is not set. "
            "Control endpoints will return 500 until token is set."
        )

    pg = PrintGuardClient(
        base_url=args.printguard_url,
        verify_ssl=args.verify_ssl,
        timeout=(args.connect_timeout, args.read_timeout),
    )

    cache = CacheState()
    cache_lock = threading.Lock()
    stop_evt = threading.Event()

    t = threading.Thread(
        target=poller_thread_fn,
        name="printguard-poller",
        args=(pg, cache, cache_lock, stop_evt, float(args.poll_interval)),
        daemon=True,
    )
    t.start()

    app = create_app(
        pg=pg,
        cache=cache,
        cache_lock=cache_lock,
        poll_interval_sec=float(args.poll_interval),
        enable_control=bool(args.enable_control),
        auth_token=auth_token,
    )

    log.info("Bridge listening on http://%s:%d", args.bind_host, int(args.bind_port))

    # Flask dev server; for "production-ish" use behind a real WSGI server.
    # For most LAN/home-automation use cases, this is fine.
    try:
        app.run(host=args.bind_host, port=int(args.bind_port), debug=False, use_reloader=False)
    finally:
        stop_evt.set()


if __name__ == "__main__":
    main()
