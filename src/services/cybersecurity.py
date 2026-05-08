"""Reusable cybersecurity workflows for demos, tests, and future APIs."""

from __future__ import annotations

import datetime
import csv
import hashlib
import io
import json
import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from src.cybersecurity import (
    IntrusionPreventionSystem,
    SecurityInformationEventManagement,
)
from src.cybersecurity.ids_ips import Alert, AlertStatus, NetworkEvent
from src.cybersecurity.siem import (
    AuthenticationEvent,
    AuthenticationResult,
    EventCategory,
    EventSeverity,
    SecurityEvent,
)
from src.storage import CybersecurityEventStore

ROLE_PERMISSIONS = {
    "analyst": {"import_csv", "acknowledge_alert", "add_alert_note"},
    "admin": {
        "import_csv",
        "acknowledge_alert",
        "add_alert_note",
        "resolve_alert",
        "manage_operators",
    },
}


class CybersecurityMonitoringService:
    """Stateful service for ingesting events and querying current security state."""

    def __init__(
        self,
        ips: Optional[IntrusionPreventionSystem] = None,
        siem: Optional[SecurityInformationEventManagement] = None,
        store: Optional[CybersecurityEventStore] = None,
    ) -> None:
        self.ips = ips or IntrusionPreventionSystem()
        self.siem = siem or SecurityInformationEventManagement()
        self.store = store
        self._memory_operator_accounts = (
            {} if store is not None else _build_default_operator_accounts()
        )
        self._memory_processed_imports: set[str] = set()
        self._rehydrate_from_store()

    def ingest_network_events(self, events: Iterable[NetworkEvent]) -> Dict[str, Any]:
        event_list = list(events)
        latest_alert = self._ingest_network_events(event_list)
        if self.store is not None:
            self.store.save_network_events(event_list)
        return {
            "ingested_events": len(event_list),
            "latest_alert": latest_alert.description if latest_alert else None,
            "auto_blocked_ips": self.ips.auto_blocked_ips,
            "dashboard": self.get_dashboard()["ips"],
        }

    def ingest_security_events(self, events: Iterable[SecurityEvent]) -> Dict[str, Any]:
        event_list = list(events)
        self._ingest_security_events(event_list)
        if self.store is not None:
            self.store.save_security_events(event_list)
        return {
            "ingested_events": len(event_list),
            "dashboard": self.get_dashboard()["siem"],
            "triggered_rules": self.get_triggered_rules(),
        }

    def ingest_auth_events(
        self,
        events: Iterable[AuthenticationEvent],
    ) -> Dict[str, Any]:
        auth_event_list = list(events)
        security_event_list = [
            event.to_security_event()
            for event in auth_event_list
        ]
        self._ingest_security_events(security_event_list)
        if self.store is not None:
            self.store.save_security_events(security_event_list)
            self.store.save_auth_events(auth_event_list)
        return {
            "ingested_events": len(security_event_list),
            "auth_events": len(auth_event_list),
            "dashboard": self.get_dashboard()["siem"],
            "triggered_rules": self.get_triggered_rules(),
        }

    def ingest_network_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.ingest_network_events(_parse_network_events(payload))

    def ingest_security_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.ingest_security_events(_parse_security_events(payload))

    def ingest_auth_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.ingest_auth_events(_parse_auth_events(payload))

    def import_network_csv(
        self,
        payload: Dict[str, Any],
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        imported_from = _describe_csv_source(payload)
        try:
            events = _load_network_events_from_csv_payload(payload)
            result = self.ingest_network_events(events)
        except ValueError as exc:
            if self.store is not None:
                self.store.record_import_history(
                    imported_from,
                    "network_csv",
                    operator_name=operator_name,
                    status="failed",
                    error_message=str(exc),
                )
                self.store.record_audit_event(
                    operator_name=operator_name,
                    action_type="import_network_csv",
                    target=imported_from,
                    status="failed",
                    details={"error_message": str(exc)},
                )
            raise
        if self.store is not None:
            self.store.record_import_history(
                imported_from,
                "network_csv",
                operator_name=operator_name,
                status="success",
            )
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="import_network_csv",
                target=imported_from,
                status="success",
                details={"ingested_events": result["ingested_events"]},
            )
        result["imported_from"] = imported_from
        result["operator_name"] = operator_name
        return result

    def import_security_csv(
        self,
        payload: Dict[str, Any],
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        imported_from = _describe_csv_source(payload)
        try:
            events = _load_security_events_from_csv_payload(payload)
            result = self.ingest_security_events(events)
        except ValueError as exc:
            if self.store is not None:
                self.store.record_import_history(
                    imported_from,
                    "security_csv",
                    operator_name=operator_name,
                    status="failed",
                    error_message=str(exc),
                )
                self.store.record_audit_event(
                    operator_name=operator_name,
                    action_type="import_security_csv",
                    target=imported_from,
                    status="failed",
                    details={"error_message": str(exc)},
                )
            raise
        if self.store is not None:
            self.store.record_import_history(
                imported_from,
                "security_csv",
                operator_name=operator_name,
                status="success",
            )
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="import_security_csv",
                target=imported_from,
                status="success",
                details={"ingested_events": result["ingested_events"]},
            )
        result["imported_from"] = imported_from
        result["operator_name"] = operator_name
        return result

    def import_auth_csv(
        self,
        payload: Dict[str, Any],
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        imported_from = _describe_csv_source(payload)
        try:
            events = _load_auth_events_from_csv_payload(payload)
            result = self.ingest_auth_events(events)
        except ValueError as exc:
            if self.store is not None:
                self.store.record_import_history(
                    imported_from,
                    "auth_csv",
                    operator_name=operator_name,
                    status="failed",
                    error_message=str(exc),
                )
                self.store.record_audit_event(
                    operator_name=operator_name,
                    action_type="import_auth_csv",
                    target=imported_from,
                    status="failed",
                    details={"error_message": str(exc)},
                )
            raise
        if self.store is not None:
            self.store.record_import_history(
                imported_from,
                "auth_csv",
                operator_name=operator_name,
                status="success",
            )
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="import_auth_csv",
                target=imported_from,
                status="success",
                details={"ingested_events": result["ingested_events"]},
            )
        result["imported_from"] = imported_from
        result["operator_name"] = operator_name
        return result

    def scan_csv_directory(
        self,
        directory_path: str,
        target: str,
        operator_name: str = "system",
        pattern: str = "*.csv",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        normalized_target = _normalize_import_target(target)
        directory = Path(directory_path)
        if not directory.exists():
            raise ValueError(f"Directory '{directory_path}' was not found")
        if not directory.is_dir():
            raise ValueError(f"Path '{directory_path}' is not a directory")
        if not str(pattern).strip():
            raise ValueError("pattern is required")

        matched_files = sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and fnmatch.fnmatch(path.name, pattern)
        )
        imported_files = 0
        skipped_files = 0
        failed_files = 0
        results: List[Dict[str, Any]] = []

        for file_path in matched_files:
            try:
                file_key = _build_import_file_key(file_path, normalized_target)
                if self._has_processed_import(file_key):
                    skipped_files += 1
                    results.append(
                        {
                            "file_path": str(file_path),
                            "status": "skipped",
                            "reason": "already_processed",
                        }
                    )
                    continue

                if normalized_target == "network":
                    import_result = self.import_network_csv(
                        {"csv_path": str(file_path)},
                        operator_name=operator_name,
                    )
                elif normalized_target == "auth":
                    import_result = self.import_auth_csv(
                        {"csv_path": str(file_path)},
                        operator_name=operator_name,
                    )
                else:
                    import_result = self.import_security_csv(
                        {"csv_path": str(file_path)},
                        operator_name=operator_name,
                    )
            except (OSError, ValueError) as exc:
                failed_files += 1
                results.append(
                    {
                        "file_path": str(file_path),
                        "status": "failed",
                        "error": str(exc),
                    }
                )
                continue

            imported_files += 1
            self._mark_processed_import(
                file_key,
                str(file_path),
                f"{normalized_target}_csv",
            )
            results.append(
                {
                    "file_path": str(file_path),
                    "status": "imported",
                    "ingested_events": import_result["ingested_events"],
                }
            )

        if self.store is not None:
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="scan_csv_directory",
                target=str(directory),
                status="success",
                details={
                    "target": normalized_target,
                    "pattern": pattern,
                    "scanned_files": len(matched_files),
                    "imported_files": imported_files,
                    "skipped_files": skipped_files,
                    "failed_files": failed_files,
                },
            )

        return {
            "directory_path": str(directory),
            "target": normalized_target,
            "pattern": pattern,
            "scanned_files": len(matched_files),
            "imported_files": imported_files,
            "skipped_files": skipped_files,
            "failed_files": failed_files,
            "results": results,
            "operator_name": operator_name,
        }

    def get_alerts(
        self,
        threat_level: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        threat_level = _normalize_optional_filter(threat_level)
        status = _normalize_optional_filter(status)
        source_ip = _normalize_optional_filter(source_ip)
        destination_ip = _normalize_optional_filter(destination_ip)
        protocol = _normalize_optional_filter(protocol)
        query = _normalize_optional_filter(query)
        if port is not None and port <= 0:
            raise ValueError("port must be greater than 0")

        alerts = [_serialize_alert(alert) for alert in self.ips.alerts]
        if threat_level is not None:
            alerts = [
                alert
                for alert in alerts
                if _matches_exact_filter(alert["threat_level"], threat_level)
            ]
        if status is not None:
            alerts = [
                alert
                for alert in alerts
                if _matches_exact_filter(alert["status"], status)
            ]
        if source_ip is not None:
            alerts = [
                alert
                for alert in alerts
                if _matches_exact_filter(alert["source_ip"], source_ip)
            ]
        if destination_ip is not None:
            alerts = [
                alert
                for alert in alerts
                if _matches_exact_filter(alert["destination_ip"], destination_ip)
            ]
        if protocol is not None:
            alerts = [
                alert
                for alert in alerts
                if _matches_exact_filter(alert["protocol"], protocol)
            ]
        if port is not None:
            alerts = [alert for alert in alerts if alert["port"] == port]
        if query is not None:
            alerts = [alert for alert in alerts if _matches_alert_query(alert, query)]
        alerts.sort(key=lambda alert: alert["created_at"], reverse=True)
        if limit is not None:
            alerts = alerts[:limit]
        return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for alert in self.get_alerts():
            if alert["alert_id"] == alert_id:
                return alert
        return None

    def get_alert_investigation(
        self,
        alert_id: str,
        activity_limit: int = 10,
        related_limit: int = 5,
    ) -> Optional[Dict[str, Any]]:
        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            return None
        activity_log = self.get_audit_log(limit=activity_limit, target=alert_id)
        related_alerts = self._get_related_alerts(alert, limit=related_limit)
        auth_activity = self._get_related_auth_activity(alert, limit=activity_limit)
        related_rule_activity = self._get_related_rule_activity(
            alert,
            limit=related_limit,
        )
        return {
            "alert": alert,
            "timeline": self._build_investigation_timeline(
                alert,
                activity_log=activity_log,
                auth_activity=auth_activity,
                related_rule_activity=related_rule_activity,
            ),
            "activity_log": activity_log,
            "related_alerts": related_alerts,
            "auth_activity": auth_activity,
            "related_rule_activity": related_rule_activity,
        }

    def acknowledge_alert(
        self,
        alert_id: str,
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        alert = self._find_alert_object(alert_id)
        if alert is None:
            raise ValueError(f"Alert '{alert_id}' was not found")
        if alert.status == AlertStatus.RESOLVED:
            raise ValueError("Resolved alerts cannot be acknowledged")
        alert.acknowledge()
        self._persist_alert_state(alert)
        serialized = _serialize_alert(alert)
        if self.store is not None:
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="acknowledge_alert",
                target=alert_id,
                status="success",
                details={"status": serialized["status"]},
            )
        serialized["updated_by"] = operator_name
        return serialized

    def add_alert_note(
        self,
        alert_id: str,
        note: str,
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            raise ValueError(f"Alert '{alert_id}' was not found")
        normalized_note = str(note).strip()
        if not normalized_note:
            raise ValueError("note is required")
        if len(normalized_note) > 2000:
            raise ValueError("note must be 2000 characters or fewer")
        note_record = {
            "operator_name": operator_name,
            "action_type": "add_alert_note",
            "target": alert_id,
            "status": "success",
            "details": {"note": normalized_note},
        }
        if self.store is not None:
            self.store.record_audit_event(**note_record)
            stored = self.get_audit_log(limit=1, target=alert_id)
            if stored:
                return stored[0]
        note_record["created_at"] = datetime.datetime.now(datetime.UTC).isoformat()
        return note_record

    def resolve_alert(
        self,
        alert_id: str,
        operator_name: str = "system",
    ) -> Dict[str, Any]:
        operator_name = _normalize_operator_name(operator_name)
        alert = self._find_alert_object(alert_id)
        if alert is None:
            raise ValueError(f"Alert '{alert_id}' was not found")
        alert.resolve()
        self._persist_alert_state(alert)
        serialized = _serialize_alert(alert)
        if self.store is not None:
            self.store.record_audit_event(
                operator_name=operator_name,
                action_type="resolve_alert",
                target=alert_id,
                status="success",
                details={"status": serialized["status"]},
            )
        serialized["updated_by"] = operator_name
        return serialized

    def get_triggered_rules(self) -> List[Dict[str, Any]]:
        return self.siem.get_triggered_rules()

    def get_dashboard(self) -> Dict[str, Any]:
        return {
            "ips": self.ips.get_summary(),
            "siem": self.siem.get_dashboard(),
        }

    def get_import_history(self, limit: int = 20) -> List[Dict[str, str]]:
        if self.store is None:
            return []
        return self.store.load_import_history(limit=limit)

    def get_auth_events(
        self,
        username: str | None = None,
        source_ip: str | None = None,
        auth_method: str | None = None,
        result: str | None = None,
        target_resource: str | None = None,
        failure_reason: str | None = None,
        is_privileged: bool | None = None,
        query: str | None = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be greater than 0")
        username = _normalize_optional_filter(username)
        source_ip = _normalize_optional_filter(source_ip)
        auth_method = _normalize_optional_filter(auth_method)
        result = _normalize_optional_filter(result)
        target_resource = _normalize_optional_filter(target_resource)
        failure_reason = _normalize_optional_filter(failure_reason)
        query = _normalize_optional_filter(query)
        if result is not None:
            _parse_enum(result, AuthenticationResult, "result")

        if self.store is not None:
            events = self.store.load_auth_events(
                username=username,
                source_ip=source_ip,
                auth_method=auth_method,
                result=result,
                target_resource=target_resource,
                failure_reason=failure_reason,
                is_privileged=is_privileged,
                query=query,
                limit=limit,
            )
            return [_serialize_auth_event(event) for event in events]

        events = [
            _serialize_security_event(event)
            for event in self.siem.get_events(category=EventCategory.AUTHENTICATION)
        ]
        filtered = [
            event
            for event in events
            if _matches_serialized_auth_event(
                event,
                username=username,
                source_ip=source_ip,
                auth_method=auth_method,
                result=result,
                target_resource=target_resource,
                failure_reason=failure_reason,
                is_privileged=is_privileged,
                query=query,
            )
        ]
        filtered.sort(key=lambda event: event["timestamp"], reverse=True)
        return filtered[:limit]

    def get_audit_log(
        self,
        limit: int = 20,
        target: str | None = None,
    ) -> List[Dict[str, Any]]:
        if self.store is None:
            return []
        return self.store.load_audit_log(limit=limit, target=target)

    def authenticate_operator(
        self,
        username: str,
        api_key: str,
        required_permission: str | None = None,
    ) -> Dict[str, Any]:
        normalized_username = _normalize_operator_name(username)
        if not str(api_key):
            raise ValueError("operator_key is required")
        account = self._get_operator_account(normalized_username)
        if account is None:
            raise ValueError("Operator account was not found")
        if not account["is_active"]:
            raise ValueError("Operator account is inactive")
        if account["api_key_hash"] != _hash_api_key(str(api_key)):
            raise ValueError("Invalid operator credentials")
        if required_permission is not None:
            if required_permission not in ROLE_PERMISSIONS.get(str(account["role"]), set()):
                raise PermissionError(
                    f"Operator role '{account['role']}' cannot perform '{required_permission}'"
                )
        return {
            "username": account["username"],
            "role": account["role"],
            "is_active": account["is_active"],
            "created_by": account.get("created_by"),
            "created_at": account.get("created_at"),
            "updated_at": account.get("updated_at"),
        }

    def authorize_operator(
        self,
        username: str,
        required_permission: str | None = None,
    ) -> Dict[str, Any]:
        normalized_username = _normalize_operator_name(username)
        account = self._get_operator_account(normalized_username)
        if account is None:
            raise ValueError("Operator account was not found")
        if not account["is_active"]:
            raise ValueError("Operator account is inactive")
        if required_permission is not None:
            if required_permission not in ROLE_PERMISSIONS.get(str(account["role"]), set()):
                raise PermissionError(
                    f"Operator role '{account['role']}' cannot perform '{required_permission}'"
                )
        return {
            "username": account["username"],
            "role": account["role"],
            "is_active": account["is_active"],
            "created_by": account.get("created_by"),
            "created_at": account.get("created_at"),
            "updated_at": account.get("updated_at"),
        }

    def list_operator_accounts(self) -> List[Dict[str, Any]]:
        if self.store is not None:
            return self.store.list_operator_accounts()
        return [
            {
                "username": username,
                "role": account["role"],
                "is_active": account["is_active"],
                "created_by": account.get("created_by"),
                "created_at": account.get("created_at"),
                "updated_at": account.get("updated_at"),
            }
            for username, account in sorted(self._memory_operator_accounts.items())
        ]

    def create_operator_account(
        self,
        payload: Dict[str, Any],
        created_by: str,
    ) -> Dict[str, Any]:
        username = _normalize_operator_name(payload.get("username", ""))
        api_key = str(payload.get("api_key", "")).strip()
        role = str(payload.get("role", "")).strip().lower()
        is_active = bool(payload.get("is_active", True))
        if not api_key:
            raise ValueError("api_key is required")
        if role not in ROLE_PERMISSIONS:
            raise ValueError(
                "role must be one of: " + ", ".join(sorted(ROLE_PERMISSIONS))
            )
        if self.store is not None:
            self.store.upsert_operator_account(
                username=username,
                api_key=api_key,
                role=role,
                is_active=is_active,
                created_by=created_by,
            )
            self.store.record_audit_event(
                operator_name=created_by,
                action_type="create_operator_account",
                target=username,
                status="success",
                details={"role": role, "is_active": is_active},
            )
            created = self.store.get_operator_account(username)
        else:
            created = {
                "username": username,
                "api_key_hash": _hash_api_key(api_key),
                "role": role,
                "is_active": is_active,
                "created_by": created_by,
                "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "updated_at": datetime.datetime.now(datetime.UTC).isoformat(),
            }
            self._memory_operator_accounts[username] = created
        if created is None:
            raise ValueError("Unable to create operator account")
        return {
            "username": created["username"],
            "role": created["role"],
            "is_active": created["is_active"],
            "created_by": created.get("created_by"),
            "created_at": created.get("created_at"),
            "updated_at": created.get("updated_at"),
        }

    def _ingest_network_events(
        self,
        events: List[NetworkEvent],
    ) -> Optional[Alert]:
        latest_alert: Optional[Alert] = None

        for event in events:
            alert = self.ips.analyze_event(event)
            if alert is not None:
                latest_alert = alert
                if alert.created_at > event.timestamp:
                    alert.created_at = event.timestamp

        return latest_alert

    def _ingest_security_events(self, events: List[SecurityEvent]) -> None:
        self.siem.ingest_events(events)

    def _rehydrate_from_store(self) -> None:
        if self.store is None:
            return
        historical_network_events = self.store.load_network_events()
        if historical_network_events:
            self._ingest_network_events(historical_network_events)
        historical_security_events = self.store.load_security_events()
        if historical_security_events:
            self._ingest_security_events(historical_security_events)
        self._apply_persisted_alert_states()

    def _find_alert_object(self, alert_id: str) -> Optional[Alert]:
        for alert in self.ips.alerts:
            if _serialize_alert(alert)["alert_id"] == alert_id:
                return alert
        return None

    def _persist_alert_state(self, alert: Alert) -> None:
        if self.store is None:
            return
        serialized = _serialize_alert(alert)
        self.store.upsert_alert_state(
            alert_id=serialized["alert_id"],
            status=serialized["status"],
            resolved_at=serialized["resolved_at"],
        )

    def _apply_persisted_alert_states(self) -> None:
        if self.store is None:
            return
        for alert_id, state in self.store.load_alert_states().items():
            alert = self._find_alert_object(alert_id)
            if alert is None:
                continue
            status = state["status"]
            resolved_at = state["resolved_at"]
            if status == AlertStatus.ACKNOWLEDGED.value:
                alert.status = AlertStatus.ACKNOWLEDGED
            elif status == AlertStatus.RESOLVED.value:
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = (
                    datetime.datetime.fromisoformat(resolved_at)
                    if resolved_at
                    else alert.resolved_at
                )

    def _get_operator_account(self, username: str) -> Dict[str, Any] | None:
        if self.store is not None:
            return self.store.get_operator_account(username)
        return self._memory_operator_accounts.get(username)

    def _has_processed_import(self, file_key: str) -> bool:
        if self.store is not None:
            return self.store.has_processed_import(file_key)
        return file_key in self._memory_processed_imports

    def _mark_processed_import(
        self,
        file_key: str,
        file_path: str,
        import_type: str,
    ) -> None:
        if self.store is not None:
            self.store.mark_processed_import(file_key, file_path, import_type)
            return
        self._memory_processed_imports.add(file_key)

    def _get_related_alerts(
        self,
        alert: Dict[str, Any],
        limit: int,
    ) -> List[Dict[str, Any]]:
        related_alerts: List[Dict[str, Any]] = []
        for candidate in self.get_alerts():
            if candidate["alert_id"] == alert["alert_id"]:
                continue
            relationship: List[str] = []
            if candidate["source_ip"] == alert["source_ip"]:
                relationship.append("source_ip")
            if candidate["destination_ip"] == alert["destination_ip"]:
                relationship.append("destination_ip")
            if not relationship:
                continue
            candidate_with_context = dict(candidate)
            candidate_with_context["relationship"] = ", ".join(relationship)
            related_alerts.append(candidate_with_context)
        return related_alerts[:limit]

    def _get_related_auth_activity(
        self,
        alert: Dict[str, Any],
        limit: int,
    ) -> List[Dict[str, Any]]:
        matching_events: List[Dict[str, Any]] = []
        for event in self.siem.get_events(category=EventCategory.AUTHENTICATION):
            serialized = _serialize_security_event(event)
            if serialized["source_ip"] != alert["source_ip"]:
                continue
            serialized["relationship"] = "source_ip"
            matching_events.append(serialized)
        matching_events.sort(key=lambda event: event["timestamp"], reverse=True)
        return matching_events[:limit]

    def _get_related_rule_activity(
        self,
        alert: Dict[str, Any],
        limit: int,
    ) -> List[Dict[str, Any]]:
        related_rules: List[Dict[str, Any]] = []
        for rule in reversed(self.get_triggered_rules()):
            details = rule.get("details", {}) if isinstance(rule, dict) else {}
            source_ips = [
                str(source_ip).strip()
                for source_ip in details.get("source_ips", [])
            ]
            relationship = None
            if alert["source_ip"] in source_ips:
                relationship = "source_ip"
            elif alert["destination_ip"] in source_ips:
                relationship = "destination_ip"
            if relationship is None:
                continue
            rule_with_context = dict(rule)
            rule_with_context["relationship"] = relationship
            related_rules.append(rule_with_context)
        return related_rules[:limit]

    def _build_investigation_timeline(
        self,
        alert: Dict[str, Any],
        activity_log: List[Dict[str, Any]],
        auth_activity: List[Dict[str, Any]],
        related_rule_activity: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        timeline = [
            {
                "type": "triggering_event",
                "occurred_at": alert["created_at"],
                "title": alert["description"],
                "summary": (
                    f"{alert['source_ip']} -> {alert['destination_ip']} "
                    f"on {alert['protocol']}/{alert['port']}"
                ),
                "details": {
                    "alert_id": alert["alert_id"],
                    "threat_level": alert["threat_level"],
                    "status": alert["status"],
                    "payload_size": alert["payload_size"],
                },
            }
        ]
        for rule in related_rule_activity:
            timeline.append(
                {
                    "type": "rule_match",
                    "occurred_at": rule.get("triggered_at"),
                    "title": rule.get("rule", "Correlation rule"),
                    "summary": rule.get("description", ""),
                    "details": {
                        "relationship": rule.get("relationship"),
                        "severity": rule.get("severity"),
                        "rule_details": rule.get("details", {}),
                    },
                }
            )
        for auth_event in auth_activity:
            timeline.append(
                {
                    "type": "auth_event",
                    "occurred_at": auth_event.get("timestamp"),
                    "title": (
                        f"{auth_event.get('username') or 'unknown user'} "
                        f"{auth_event.get('result') or 'auth event'}"
                    ),
                    "summary": (
                        f"{auth_event.get('source_ip') or 'unknown IP'} "
                        f"against {auth_event.get('target_resource') or 'unknown resource'}"
                    ),
                    "details": auth_event,
                }
            )
        for activity in activity_log:
            timeline.append(
                {
                    "type": "operator_action",
                    "occurred_at": activity.get("created_at"),
                    "title": str(activity.get("action_type", "operator_action")),
                    "summary": (
                        f"{activity.get('operator_name')} recorded "
                        f"{activity.get('status', 'success')}"
                    ),
                    "details": activity,
                }
            )
        timeline.sort(key=lambda entry: str(entry.get("occurred_at") or ""))
        return timeline


def build_sample_network_events() -> List[NetworkEvent]:
    """Return the default network events used by the CLI demo."""
    return [
        NetworkEvent(
            source_ip="192.168.1.10",
            destination_ip="10.0.0.1",
            port=80,
            protocol="HTTP",
            payload_size=512,
        ),
        NetworkEvent(
            source_ip="203.0.113.5",
            destination_ip="10.0.0.1",
            port=22,
            protocol="SSH",
            payload_size=256,
        ),
    ]


def build_sample_security_events() -> List[SecurityEvent]:
    """Return the default SIEM events used by the CLI demo."""
    return [event.to_security_event() for event in build_sample_auth_events()]


def build_sample_auth_events() -> List[AuthenticationEvent]:
    """Return realistic authentication events used by the CLI demo."""
    return [
        AuthenticationEvent(
            source="vpn-gateway",
            username="admin",
            source_ip="198.51.100.25",
            auth_method="password",
            result=AuthenticationResult.FAILURE,
            target_resource="vpn-console",
            is_privileged=True,
            failure_reason="bad_password",
        )
        for _ in range(5)
    ]


def process_network_events(
    events: Iterable[NetworkEvent],
    ips: Optional[IntrusionPreventionSystem] = None,
) -> Dict[str, Any]:
    """Analyze network events and return an alert summary."""
    service = CybersecurityMonitoringService(ips=ips)
    result = service.ingest_network_events(events)
    return {
        "alert": result["latest_alert"],
        "auto_blocked_ips": service.ips.auto_blocked_ips,
        "summary": service.ips.get_summary(),
    }


def process_security_events(
    events: Iterable[SecurityEvent],
    siem: Optional[SecurityInformationEventManagement] = None,
) -> Dict[str, Any]:
    """Ingest security events and return a SIEM summary."""
    service = CybersecurityMonitoringService(siem=siem)
    service.ingest_security_events(events)
    return {
        "dashboard": service.siem.get_dashboard(),
        "triggered_rules": service.siem.get_triggered_rules(),
    }


def process_auth_events(
    events: Iterable[AuthenticationEvent],
    siem: Optional[SecurityInformationEventManagement] = None,
) -> Dict[str, Any]:
    """Analyze authentication events through the SIEM workflow."""
    service = CybersecurityMonitoringService(siem=siem)
    result = service.ingest_auth_events(events)
    return {
        "dashboard": result["dashboard"],
        "triggered_rules": result["triggered_rules"],
        "auth_events": result["auth_events"],
    }


def run_sample_cybersecurity_scenario(verbose: bool = True) -> Dict[str, Any]:
    """Run the default cybersecurity workflow used by the CLI demo."""
    if verbose:
        print("\n=== 1. Network & Cybersecurity Monitoring ===")

    ips_result = process_network_events(build_sample_network_events())
    if verbose:
        print(f"  IPS alert: {ips_result['alert'] if ips_result['alert'] else 'None'}")
        print(f"  Auto-blocked IPs: {ips_result['auto_blocked_ips']}")

    siem_result = process_auth_events(build_sample_auth_events())
    if verbose:
        print(f"  SIEM dashboard: {siem_result['dashboard']}")

    return {
        "ips": ips_result,
        "siem": siem_result,
    }


def _parse_network_events(payload: Dict[str, Any]) -> List[NetworkEvent]:
    raw_events = _require_event_list(payload, "events")
    return [_parse_network_event(item) for item in raw_events]


def _parse_security_events(payload: Dict[str, Any]) -> List[SecurityEvent]:
    raw_events = _require_event_list(payload, "events")
    return [_parse_security_event(item) for item in raw_events]


def _parse_auth_events(payload: Dict[str, Any]) -> List[AuthenticationEvent]:
    raw_events = _require_event_list(payload, "events")
    return [_parse_auth_event(item) for item in raw_events]


def _require_event_list(payload: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    events = payload.get(key)
    if not isinstance(events, list) or not events:
        raise ValueError(f"'{key}' must be a non-empty list")
    if not all(isinstance(item, dict) for item in events):
        raise ValueError(f"'{key}' entries must be JSON objects")
    return events


def _parse_network_event(data: Dict[str, Any]) -> NetworkEvent:
    required = [
        "source_ip",
        "destination_ip",
        "port",
        "protocol",
        "payload_size",
    ]
    missing = [
        field
        for field in required
        if field not in data or data[field] in {None, ""}
    ]
    if missing:
        raise ValueError(
            "Missing network event fields: " + ", ".join(sorted(missing))
        )
    return NetworkEvent(
        source_ip=str(data["source_ip"]),
        destination_ip=str(data["destination_ip"]),
        port=int(data["port"]),
        protocol=str(data["protocol"]),
        payload_size=int(data["payload_size"]),
        timestamp=_parse_optional_timestamp(data.get("timestamp")),
        metadata=data.get("metadata", {}),
    )


def _parse_security_event(data: Dict[str, Any]) -> SecurityEvent:
    required = ["source", "category", "severity", "message"]
    missing = [
        field
        for field in required
        if field not in data or data[field] in {None, ""}
    ]
    if missing:
        raise ValueError(
            "Missing security event fields: " + ", ".join(sorted(missing))
        )
    return SecurityEvent(
        source=str(data["source"]),
        category=_parse_enum(
            data["category"],
            EventCategory,
            "category",
        ),
        severity=_parse_enum(
            data["severity"],
            EventSeverity,
            "severity",
        ),
        message=str(data["message"]),
        timestamp=_parse_optional_timestamp(data.get("timestamp")),
        raw_data=data.get("raw_data", {}),
    )


def _parse_auth_event(data: Dict[str, Any]) -> AuthenticationEvent:
    required = ["source", "username", "source_ip", "auth_method", "result"]
    missing = [
        field
        for field in required
        if field not in data or data[field] in {None, ""}
    ]
    if missing:
        raise ValueError(
            "Missing authentication event fields: " + ", ".join(sorted(missing))
        )
    raw_data = data.get("raw_data", {})
    if raw_data and not isinstance(raw_data, dict):
        raise ValueError("'raw_data' must be a JSON object")
    return AuthenticationEvent(
        source=str(data["source"]),
        username=str(data["username"]),
        source_ip=str(data["source_ip"]),
        auth_method=str(data["auth_method"]),
        result=_parse_enum(
            data["result"],
            AuthenticationResult,
            "result",
        ),
        timestamp=_parse_optional_timestamp(data.get("timestamp")),
        target_resource=_normalize_optional_filter(data.get("target_resource")),
        is_privileged=bool(data.get("is_privileged", False)),
        failure_reason=_normalize_optional_filter(data.get("failure_reason")),
        raw_data=raw_data,
    )


def _parse_enum(value: Any, enum_type: Any, field_name: str) -> Any:
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed_values = ", ".join(item.value for item in enum_type)
        raise ValueError(
            f"Invalid {field_name} '{value}'. Allowed values: {allowed_values}"
        ) from exc


def _parse_optional_timestamp(value: Any) -> datetime.datetime:
    if value is None:
        return datetime.datetime.now(datetime.UTC)
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string")
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("timestamp must be a valid ISO 8601 string") from exc


def _load_network_events_from_csv_payload(payload: Dict[str, Any]) -> List[NetworkEvent]:
    rows = _load_csv_rows(payload)
    events: List[NetworkEvent] = []
    for row in rows:
        event_payload: Dict[str, Any] = {
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "port": row.get("port"),
            "protocol": row.get("protocol"),
            "payload_size": row.get("payload_size"),
        }
        if row.get("timestamp"):
            event_payload["timestamp"] = row["timestamp"]
        if row.get("metadata"):
            event_payload["metadata"] = _parse_json_cell(row["metadata"], "metadata")
        events.append(_parse_network_event(event_payload))
    return events


def _load_security_events_from_csv_payload(payload: Dict[str, Any]) -> List[SecurityEvent]:
    rows = _load_csv_rows(payload)
    events: List[SecurityEvent] = []
    for row in rows:
        event_payload: Dict[str, Any] = {
            "source": row.get("source"),
            "category": row.get("category"),
            "severity": row.get("severity"),
            "message": row.get("message"),
        }
        if row.get("timestamp"):
            event_payload["timestamp"] = row["timestamp"]
        if row.get("raw_data"):
            event_payload["raw_data"] = _parse_json_cell(row["raw_data"], "raw_data")
        events.append(_parse_security_event(event_payload))
    return events


def _load_auth_events_from_csv_payload(
    payload: Dict[str, Any],
) -> List[AuthenticationEvent]:
    rows = _load_csv_rows(payload)
    events: List[AuthenticationEvent] = []
    for row in rows:
        event_payload: Dict[str, Any] = {
            "source": row.get("source"),
            "username": row.get("username"),
            "source_ip": row.get("source_ip"),
            "auth_method": row.get("auth_method"),
            "result": row.get("result"),
        }
        if row.get("timestamp"):
            event_payload["timestamp"] = row["timestamp"]
        if row.get("target_resource"):
            event_payload["target_resource"] = row["target_resource"]
        if row.get("is_privileged"):
            event_payload["is_privileged"] = _parse_csv_bool(
                row["is_privileged"],
                "is_privileged",
            )
        if row.get("failure_reason"):
            event_payload["failure_reason"] = row["failure_reason"]
        if row.get("raw_data"):
            event_payload["raw_data"] = _parse_json_cell(row["raw_data"], "raw_data")
        events.append(_parse_auth_event(event_payload))
    return events


def _load_csv_rows(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    csv_text = payload.get("csv_text")
    csv_path = payload.get("csv_path")
    if bool(csv_text) == bool(csv_path):
        raise ValueError("Provide exactly one of 'csv_text' or 'csv_path'")

    if csv_text:
        if not isinstance(csv_text, str):
            raise ValueError("'csv_text' must be a string")
        source = io.StringIO(csv_text)
    else:
        if not isinstance(csv_path, str):
            raise ValueError("'csv_path' must be a string")
        path = Path(csv_path)
        if not path.exists():
            raise ValueError(f"CSV file '{csv_path}' was not found")
        source = path.open("r", encoding="utf-8", newline="")

    with source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("CSV input must include a header row")
        rows = list(reader)

    if not rows:
        raise ValueError("CSV input must include at least one data row")
    return rows


def _parse_json_cell(value: str, field_name: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"CSV column '{field_name}' must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"CSV column '{field_name}' must contain a JSON object")
    return parsed


def _parse_csv_bool(value: str, field_name: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ValueError(
        f"CSV column '{field_name}' must be one of: true, false, 1, 0, yes, no"
    )


def _describe_csv_source(payload: Dict[str, Any]) -> str:
    if payload.get("csv_path"):
        return str(payload["csv_path"])
    if payload.get("csv_text") is not None:
        return "inline_csv_text"
    return "unknown_csv_source"


def _normalize_optional_filter(value: Any) -> str | None:
    normalized = str(value).strip() if value is not None else ""
    return normalized or None


def _matches_exact_filter(value: Any, expected: str) -> bool:
    return str(value).strip().lower() == expected.lower()


def _matches_alert_query(alert: Dict[str, Any], query: str) -> bool:
    normalized_query = query.lower()
    searchable_fields = [
        alert["alert_id"],
        alert["description"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["protocol"],
        alert["threat_level"],
        alert["status"],
        str(alert["port"]),
    ]
    return any(normalized_query in str(field).lower() for field in searchable_fields)


def _normalize_operator_name(operator_name: str) -> str:
    normalized = str(operator_name).strip()
    if not normalized:
        raise ValueError("operator_name is required")
    return normalized


def _normalize_import_target(target: str) -> str:
    normalized = str(target).strip().lower()
    if normalized not in {"network", "security", "auth"}:
        raise ValueError("target must be one of: network, security, auth")
    return normalized


def _hash_api_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_default_operator_accounts() -> Dict[str, Dict[str, Any]]:
    now = datetime.datetime.now(datetime.UTC).isoformat()
    return {
        "analyst-1": {
            "username": "analyst-1",
            "api_key_hash": _hash_api_key("icsmog-demo-key"),
            "role": "analyst",
            "is_active": True,
            "created_by": "bootstrap",
            "created_at": now,
            "updated_at": now,
        },
        "admin": {
            "username": "admin",
            "api_key_hash": _hash_api_key("icsmog-admin-key"),
            "role": "admin",
            "is_active": True,
            "created_by": "bootstrap",
            "created_at": now,
            "updated_at": now,
        },
    }


def _serialize_alert(alert: Alert) -> Dict[str, Any]:
    serialized = {
        "source_ip": alert.event.source_ip,
        "destination_ip": alert.event.destination_ip,
        "port": alert.event.port,
        "protocol": alert.event.protocol,
        "payload_size": alert.event.payload_size,
        "threat_level": alert.threat_level.value,
        "description": alert.description,
        "status": alert.status.value,
        "created_at": alert.created_at.isoformat(),
        "resolved_at": (
            alert.resolved_at.isoformat() if alert.resolved_at else None
        ),
    }
    serialized["alert_id"] = _build_alert_id(serialized)
    return serialized


def _serialize_security_event(event: SecurityEvent) -> Dict[str, Any]:
    raw_data = event.raw_data if isinstance(event.raw_data, dict) else {}
    return {
        "source": event.source,
        "category": event.category.value,
        "severity": event.severity.value,
        "message": event.message,
        "timestamp": event.timestamp.isoformat(),
        "username": raw_data.get("username"),
        "source_ip": raw_data.get("source_ip"),
        "auth_method": raw_data.get("auth_method"),
        "result": raw_data.get("result"),
        "target_resource": raw_data.get("target_resource"),
        "is_privileged": bool(raw_data.get("is_privileged", False)),
        "failure_reason": raw_data.get("failure_reason"),
        "raw_data": raw_data,
    }


def _serialize_auth_event(event: AuthenticationEvent) -> Dict[str, Any]:
    return {
        "source": event.source,
        "username": event.username,
        "source_ip": event.source_ip,
        "auth_method": event.auth_method,
        "result": event.result.value,
        "target_resource": event.target_resource,
        "is_privileged": event.is_privileged,
        "failure_reason": event.failure_reason,
        "timestamp": event.timestamp.isoformat(),
        "raw_data": event.raw_data,
    }


def _matches_serialized_auth_event(
    event: Dict[str, Any],
    username: str | None = None,
    source_ip: str | None = None,
    auth_method: str | None = None,
    result: str | None = None,
    target_resource: str | None = None,
    failure_reason: str | None = None,
    is_privileged: bool | None = None,
    query: str | None = None,
) -> bool:
    if username is not None and str(event.get("username", "")).lower() != username.lower():
        return False
    if source_ip is not None and str(event.get("source_ip", "")).lower() != source_ip.lower():
        return False
    if auth_method is not None and str(event.get("auth_method", "")).lower() != auth_method.lower():
        return False
    if result is not None and str(event.get("result", "")).lower() != result.lower():
        return False
    if target_resource is not None and str(event.get("target_resource") or "").lower() != target_resource.lower():
        return False
    if failure_reason is not None and str(event.get("failure_reason") or "").lower() != failure_reason.lower():
        return False
    if is_privileged is not None and bool(event.get("is_privileged")) is not is_privileged:
        return False
    if query is None:
        return True
    normalized_query = query.lower()
    searchable_fields = [
        event.get("source"),
        event.get("username"),
        event.get("source_ip"),
        event.get("auth_method"),
        event.get("result"),
        event.get("target_resource"),
        event.get("failure_reason"),
    ]
    return any(normalized_query in str(field or "").lower() for field in searchable_fields)


def _build_alert_id(serialized_alert: Dict[str, Any]) -> str:
    fingerprint = "|".join(
        [
            serialized_alert["source_ip"],
            serialized_alert["destination_ip"],
            str(serialized_alert["port"]),
            serialized_alert["protocol"],
            str(serialized_alert["payload_size"]),
            serialized_alert["created_at"],
            serialized_alert["description"],
        ]
    )
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:12]


def _build_import_file_key(path: Path, target: str) -> str:
    digest = hashlib.sha256()
    digest.update(target.encode("utf-8"))
    digest.update(b"\0")
    digest.update(path.read_bytes())
    return digest.hexdigest()
