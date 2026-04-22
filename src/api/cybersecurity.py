"""Minimal HTTP API for ICSMOG cybersecurity workflows."""

from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from typing import Any, Dict, Tuple

from src.api.dashboard import render_alert_detail_html, render_dashboard_html
from src.services.cybersecurity import CybersecurityMonitoringService
from src.storage import CybersecurityEventStore


def run_cybersecurity_api_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    storage_path: str = "data/cybersecurity.db",
) -> None:
    """Run the cybersecurity API server until interrupted."""
    service = CybersecurityMonitoringService(
        store=CybersecurityEventStore(storage_path)
    )
    server = ThreadingHTTPServer(
        (host, port),
        build_handler(service),
    )
    print(f"ICSMOG cybersecurity API listening on http://{host}:{port}")
    print(f"Using SQLite storage at {storage_path}")
    print("Available endpoints: GET /, GET /dashboard, GET /health, GET /cybersecurity/dashboard, "
      "GET /cybersecurity/alerts, GET /cybersecurity/alerts/<id>/investigation, GET /cybersecurity/import-history, GET /cybersecurity/audit-log, GET /cybersecurity/me, "
      "GET /cybersecurity/operators, POST /cybersecurity/login, POST /cybersecurity/logout, "
      "POST /cybersecurity/operators, POST /cybersecurity/import/scan-directory, POST /cybersecurity/network-events, "
          "POST /cybersecurity/security-events, POST /cybersecurity/auth-events, POST /cybersecurity/import/network-csv, "
          "POST /cybersecurity/import/security-csv, POST /cybersecurity/import/auth-csv, POST /cybersecurity/alerts/<id>/acknowledge, "
          "POST /cybersecurity/alerts/<id>/resolve")
    print("Bootstrap accounts: analyst-1 / icsmog-demo-key, admin / icsmog-admin-key")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ICSMOG cybersecurity API.")
    finally:
        server.server_close()


def build_handler(
    service: CybersecurityMonitoringService,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to a specific service instance."""
    sessions: dict[str, dict[str, Any]] = {}

    class CybersecurityAPIHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path in {"/", "/dashboard"}:
                self._send_html(HTTPStatus.OK, render_dashboard_html())
                return

            if path.startswith("/dashboard/alerts/"):
                alert_id = path.removeprefix("/dashboard/alerts/")
                self._send_html(HTTPStatus.OK, render_alert_detail_html(alert_id))
                return

            if path == "/health":
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "ok", "service": "icsmog-cybersecurity-api"},
                )
                return

            if path == "/cybersecurity/dashboard":
                self._send_json(HTTPStatus.OK, service.get_dashboard())
                return

            if path.startswith("/cybersecurity/alerts/") and path.endswith(
                "/investigation"
            ):
                alert_id = path.removeprefix("/cybersecurity/alerts/").removesuffix(
                    "/investigation"
                )
                investigation = service.get_alert_investigation(
                    alert_id,
                    activity_limit=_get_query_int(query, "activity_limit") or 10,
                    related_limit=_get_query_int(query, "related_limit") or 5,
                )
                if investigation is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": "Alert not found", "alert_id": alert_id},
                    )
                    return
                self._send_json(HTTPStatus.OK, investigation)
                return

            if path.startswith("/cybersecurity/alerts/"):
                alert_id = path.removeprefix("/cybersecurity/alerts/")
                alert = service.get_alert_by_id(alert_id)
                if alert is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": "Alert not found", "alert_id": alert_id},
                    )
                    return
                self._send_json(HTTPStatus.OK, alert)
                return

            if path == "/cybersecurity/alerts":
                try:
                    alerts = service.get_alerts(
                        threat_level=_get_query_value(query, "threat_level"),
                        status=_get_query_value(query, "status"),
                        source_ip=_get_query_value(query, "source_ip"),
                        destination_ip=_get_query_value(query, "destination_ip"),
                        protocol=_get_query_value(query, "protocol"),
                        port=_get_query_int(query, "port"),
                        query=_get_query_value(query, "query"),
                        limit=_get_query_int(query, "limit"),
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "alerts": alerts,
                        "triggered_rules": service.get_triggered_rules(),
                    },
                )
                return

            if path == "/cybersecurity/import-history":
                try:
                    limit = _get_query_int(query, "limit") or 20
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "imports": service.get_import_history(limit=limit),
                    },
                )
                return

            if path == "/cybersecurity/audit-log":
                try:
                    limit = _get_query_int(query, "limit") or 20
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "audit_log": service.get_audit_log(limit=limit),
                    },
                )
                return

            if path == "/cybersecurity/me":
                operator = self._require_operator()
                if operator is None:
                    return
                self._send_json(HTTPStatus.OK, {"operator": operator})
                return

            if path == "/cybersecurity/operators":
                operator = self._require_operator("manage_operators")
                if operator is None:
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "operators": service.list_operator_accounts(),
                        "requested_by": operator["username"],
                    },
                )
                return

            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "Not found", "path": path},
            )

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path

            if path == "/cybersecurity/login":
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                username = str(payload.get("username", "")).strip()
                api_key = str(payload.get("api_key", ""))
                try:
                    operator = service.authenticate_operator(username, api_key)
                except ValueError as exc:
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {"error": str(exc)},
                    )
                    return
                session_id = secrets.token_urlsafe(32)
                sessions[session_id] = {"username": operator["username"]}
                self._send_json(
                    HTTPStatus.OK,
                    {"operator": operator},
                    cookies=[_build_session_cookie("icsmog_session", session_id)],
                )
                return

            if path == "/cybersecurity/logout":
                session_id = self._get_session_id()
                if session_id is not None:
                    sessions.pop(session_id, None)
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "logged_out"},
                    cookies=[_build_session_cookie("icsmog_session", "", max_age=0)],
                )
                return

            if path.startswith("/cybersecurity/alerts/") and path.endswith(
                "/acknowledge"
            ):
                operator = self._require_operator("acknowledge_alert")
                if operator is None:
                    return
                alert_id = path.removeprefix("/cybersecurity/alerts/").removesuffix(
                    "/acknowledge"
                )
                try:
                    result = service.acknowledge_alert(
                        alert_id,
                        operator_name=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(
                        HTTPStatus.NOT_FOUND
                        if "not found" in str(exc).lower()
                        else HTTPStatus.BAD_REQUEST,
                        {"error": str(exc), "alert_id": alert_id},
                    )
                    return
                self._send_json(HTTPStatus.OK, result)
                return

            if path.startswith("/cybersecurity/alerts/") and path.endswith("/resolve"):
                operator = self._require_operator("resolve_alert")
                if operator is None:
                    return
                alert_id = path.removeprefix("/cybersecurity/alerts/").removesuffix(
                    "/resolve"
                )
                try:
                    result = service.resolve_alert(
                        alert_id,
                        operator_name=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(
                        HTTPStatus.NOT_FOUND
                        if "not found" in str(exc).lower()
                        else HTTPStatus.BAD_REQUEST,
                        {"error": str(exc), "alert_id": alert_id},
                    )
                    return
                self._send_json(HTTPStatus.OK, result)
                return

            if path == "/cybersecurity/import/network-csv":
                operator = self._require_operator("import_csv")
                if operator is None:
                    return
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                try:
                    result = service.import_network_csv(
                        payload,
                        operator_name=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path == "/cybersecurity/import/security-csv":
                operator = self._require_operator("import_csv")
                if operator is None:
                    return
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                try:
                    result = service.import_security_csv(
                        payload,
                        operator_name=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path == "/cybersecurity/import/auth-csv":
                operator = self._require_operator("import_csv")
                if operator is None:
                    return
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                try:
                    result = service.import_auth_csv(
                        payload,
                        operator_name=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path == "/cybersecurity/import/scan-directory":
                operator = self._require_operator("import_csv")
                if operator is None:
                    return
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                try:
                    result = service.scan_csv_directory(
                        directory_path=str(payload.get("directory_path", "")),
                        target=str(payload.get("target", "")),
                        operator_name=operator["username"],
                        pattern=str(payload.get("pattern", "*.csv")),
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, result)
                return

            if path == "/cybersecurity/operators":
                operator = self._require_operator("manage_operators")
                if operator is None:
                    return
                payload, error = self._read_json_body()
                if error is not None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                try:
                    result = service.create_operator_account(
                        payload,
                        created_by=operator["username"],
                    )
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path not in {
                "/cybersecurity/network-events",
                "/cybersecurity/security-events",
                "/cybersecurity/auth-events",
            }:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "Not found", "path": path},
                )
                return

            payload, error = self._read_json_body()
            if error is not None:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                return

            if path == "/cybersecurity/network-events":
                try:
                    result = service.ingest_network_payload(payload)
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path == "/cybersecurity/security-events":
                try:
                    result = service.ingest_security_payload(payload)
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

            if path == "/cybersecurity/auth-events":
                try:
                    result = service.ingest_auth_payload(payload)
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.CREATED, result)
                return

        def log_message(self, format: str, *args: object) -> None:
            """Keep API output quiet during tests and CLI runs."""
            return

        def _read_json_body(self) -> Tuple[Dict[str, Any], str | None]:
            content_length = self.headers.get("Content-Length")
            if not content_length:
                return {}, "Request body is required"

            try:
                raw_body = self.rfile.read(int(content_length))
            except ValueError:
                return {}, "Invalid Content-Length header"

            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                return {}, "Request body must be valid JSON"

            if not isinstance(payload, dict):
                return {}, "Request body must be a JSON object"
            return payload, None

        def _send_json(
            self,
            status: HTTPStatus,
            payload: Dict[str, Any],
            cookies: list[str] | None = None,
        ) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for cookie in cookies or []:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, status: HTTPStatus, payload: str) -> None:
            body = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _require_operator(
            self,
            required_permission: str | None = None,
        ) -> Dict[str, Any] | None:
            session_id = self._get_session_id()
            if session_id is not None:
                return self._authenticate_session(
                    session_id,
                    required_permission=required_permission,
                )
            operator_name = self.headers.get("X-Operator-Name", "").strip()
            operator_key = self.headers.get("X-Operator-Key", "")
            if not operator_name:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "X-Operator-Name header is required for this action"},
                )
                return None
            try:
                return service.authenticate_operator(
                    operator_name,
                    operator_key,
                    required_permission=required_permission,
                )
            except PermissionError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc)},
                )
                return None
            except ValueError as exc:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": str(exc)},
                )
                return None

        def _authenticate_session(
            self,
            session_id: str,
            required_permission: str | None = None,
        ) -> Dict[str, Any] | None:
            session = sessions.get(session_id)
            if session is None:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Session expired. Sign in again."},
                    cookies=[_build_session_cookie("icsmog_session", "", max_age=0)],
                )
                return None
            try:
                return service.authorize_operator(
                    str(session["username"]),
                    required_permission=required_permission,
                )
            except PermissionError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc)},
                )
                return None
            except ValueError:
                sessions.pop(session_id, None)
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Session expired. Sign in again."},
                    cookies=[_build_session_cookie("icsmog_session", "", max_age=0)],
                )
                return None

        def _get_session_id(self) -> str | None:
            raw_cookie = self.headers.get("Cookie")
            if not raw_cookie:
                return None
            cookie = SimpleCookie()
            cookie.load(raw_cookie)
            morsel = cookie.get("icsmog_session")
            if morsel is None or not morsel.value:
                return None
            return morsel.value

    return CybersecurityAPIHandler


def _get_query_value(query: Dict[str, list[str]], key: str) -> str | None:
    value = query.get(key, [None])[0]
    if value is None or value == "":
        return None
    return value


def _get_query_int(query: Dict[str, list[str]], key: str) -> int | None:
    value = _get_query_value(query, key)
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"Query parameter '{key}' must be an integer") from exc
    return parsed if parsed > 0 else None


def _build_session_cookie(name: str, value: str, max_age: int | None = None) -> str:
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["path"] = "/"
    cookie[name]["httponly"] = True
    cookie[name]["samesite"] = "Lax"
    if max_age is not None:
        cookie[name]["max-age"] = str(max_age)
    return cookie.output(header="").strip()
