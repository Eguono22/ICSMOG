"""SQLite persistence for cybersecurity event history."""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import List

from src.cybersecurity.ids_ips import NetworkEvent
from src.cybersecurity.siem import EventCategory, EventSeverity, SecurityEvent


class CybersecurityEventStore:
    """Persist raw cybersecurity events so service state survives restarts."""

    def __init__(self, db_path: str = "data/cybersecurity.db") -> None:
        self.db_path = Path(db_path)
        if self.db_path.parent != Path("."):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def save_network_events(self, events: List[NetworkEvent]) -> None:
        if not events:
            return
        with _open_connection(self.db_path) as connection:
            connection.executemany(
                """
                INSERT INTO network_events (
                    source_ip,
                    destination_ip,
                    port,
                    protocol,
                    payload_size,
                    timestamp,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        event.source_ip,
                        event.destination_ip,
                        event.port,
                        event.protocol,
                        event.payload_size,
                        event.timestamp.isoformat(),
                        json.dumps(event.metadata),
                    )
                    for event in events
                ],
            )

    def save_security_events(self, events: List[SecurityEvent]) -> None:
        if not events:
            return
        with _open_connection(self.db_path) as connection:
            connection.executemany(
                """
                INSERT INTO security_events (
                    source,
                    category,
                    severity,
                    message,
                    timestamp,
                    raw_data
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        event.source,
                        event.category.value,
                        event.severity.value,
                        event.message,
                        event.timestamp.isoformat(),
                        json.dumps(event.raw_data),
                    )
                    for event in events
                ],
            )

    def load_network_events(self) -> List[NetworkEvent]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    source_ip,
                    destination_ip,
                    port,
                    protocol,
                    payload_size,
                    timestamp,
                    metadata
                FROM network_events
                ORDER BY id ASC
                """
            ).fetchall()
        return [
            NetworkEvent(
                source_ip=row[0],
                destination_ip=row[1],
                port=row[2],
                protocol=row[3],
                payload_size=row[4],
                timestamp=_parse_timestamp(row[5]),
                metadata=json.loads(row[6]),
            )
            for row in rows
        ]

    def load_security_events(self) -> List[SecurityEvent]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    source,
                    category,
                    severity,
                    message,
                    timestamp,
                    raw_data
                FROM security_events
                ORDER BY id ASC
                """
            ).fetchall()
        return [
            SecurityEvent(
                source=row[0],
                category=EventCategory(row[1]),
                severity=EventSeverity(row[2]),
                message=row[3],
                timestamp=_parse_timestamp(row[4]),
                raw_data=json.loads(row[5]),
            )
            for row in rows
        ]

    def upsert_alert_state(
        self,
        alert_id: str,
        status: str,
        resolved_at: str | None,
    ) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO alert_states (
                    alert_id,
                    status,
                    resolved_at,
                    updated_at
                ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(alert_id) DO UPDATE SET
                    status = excluded.status,
                    resolved_at = excluded.resolved_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (alert_id, status, resolved_at),
            )

    def load_alert_states(self) -> dict[str, dict[str, str | None]]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    alert_id,
                    status,
                    resolved_at
                FROM alert_states
                """
            ).fetchall()
        return {
            row[0]: {
                "status": row[1],
                "resolved_at": row[2],
            }
            for row in rows
        }

    def has_processed_import(self, file_key: str) -> bool:
        with _open_connection(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM imported_files
                WHERE file_key = ?
                """,
                (file_key,),
            ).fetchone()
        return row is not None

    def mark_processed_import(
        self,
        file_key: str,
        file_path: str,
        import_type: str,
    ) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO imported_files (
                    file_key,
                    file_path,
                    import_type,
                    imported_at
                ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(file_key) DO NOTHING
                """,
                (file_key, file_path, import_type),
            )

    def record_import_history(
        self,
        file_path: str,
        import_type: str,
        operator_name: str | None = None,
        status: str = "success",
        error_message: str | None = None,
    ) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO import_history (
                    file_path,
                    import_type,
                    operator_name,
                    status,
                    error_message,
                    imported_at
                ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (file_path, import_type, operator_name, status, error_message),
            )

    def load_import_history(self, limit: int = 20) -> list[dict[str, str]]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    file_path,
                    import_type,
                    operator_name,
                    status,
                    error_message,
                    imported_at
                FROM import_history
                ORDER BY imported_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "file_path": row[0],
                "import_type": row[1],
                "operator_name": row[2],
                "status": row[3],
                "error_message": row[4],
                "imported_at": row[5],
            }
            for row in rows
        ]

    def record_audit_event(
        self,
        operator_name: str,
        action_type: str,
        target: str,
        status: str = "success",
        details: dict | None = None,
    ) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO audit_log (
                    operator_name,
                    action_type,
                    target,
                    status,
                    details,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    operator_name,
                    action_type,
                    target,
                    status,
                    json.dumps(details or {}),
                ),
            )

    def load_audit_log(self, limit: int = 20) -> list[dict[str, str | dict]]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    operator_name,
                    action_type,
                    target,
                    status,
                    details,
                    created_at
                FROM audit_log
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "operator_name": row[0],
                "action_type": row[1],
                "target": row[2],
                "status": row[3],
                "details": json.loads(row[4]) if row[4] else {},
                "created_at": row[5],
            }
            for row in rows
        ]

    def upsert_operator_account(
        self,
        username: str,
        api_key: str,
        role: str,
        is_active: bool = True,
        created_by: str | None = None,
    ) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO operator_accounts (
                    username,
                    api_key_hash,
                    role,
                    is_active,
                    created_by,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET
                    api_key_hash = excluded.api_key_hash,
                    role = excluded.role,
                    is_active = excluded.is_active,
                    created_by = COALESCE(excluded.created_by, operator_accounts.created_by),
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    username,
                    _hash_api_key(api_key),
                    role,
                    1 if is_active else 0,
                    created_by,
                ),
            )

    def get_operator_account(self, username: str) -> dict[str, str | bool] | None:
        with _open_connection(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT
                    username,
                    api_key_hash,
                    role,
                    is_active,
                    created_by,
                    created_at,
                    updated_at
                FROM operator_accounts
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if row is None:
            return None
        return {
            "username": row[0],
            "api_key_hash": row[1],
            "role": row[2],
            "is_active": bool(row[3]),
            "created_by": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def list_operator_accounts(self) -> list[dict[str, str | bool | None]]:
        with _open_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    username,
                    role,
                    is_active,
                    created_by,
                    created_at,
                    updated_at
                FROM operator_accounts
                ORDER BY username ASC
                """
            ).fetchall()
        return [
            {
                "username": row[0],
                "role": row[1],
                "is_active": bool(row[2]),
                "created_by": row[3],
                "created_at": row[4],
                "updated_at": row[5],
            }
            for row in rows
        ]

    def count_operator_accounts(self) -> int:
        with _open_connection(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM operator_accounts
                """
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def _initialize(self) -> None:
        with _open_connection(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    payload_size INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    raw_data TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_states (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    resolved_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS imported_files (
                    file_key TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    import_type TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS import_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    import_type TEXT NOT NULL,
                    operator_name TEXT,
                    status TEXT NOT NULL DEFAULT 'success',
                    error_message TEXT,
                    imported_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operator_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'success',
                    details TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_accounts (
                    username TEXT PRIMARY KEY,
                    api_key_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(import_history)")
            }
            if "operator_name" not in columns:
                connection.execute(
                    """
                    ALTER TABLE import_history
                    ADD COLUMN operator_name TEXT
                    """
                )
            if "status" not in columns:
                connection.execute(
                    """
                    ALTER TABLE import_history
                    ADD COLUMN status TEXT NOT NULL DEFAULT 'success'
                    """
                )
            if "error_message" not in columns:
                connection.execute(
                    """
                    ALTER TABLE import_history
                    ADD COLUMN error_message TEXT
                    """
                )
        self._seed_default_operator_accounts()

    def _seed_default_operator_accounts(self) -> None:
        if self.count_operator_accounts() > 0:
            return
        self.upsert_operator_account(
            username="analyst-1",
            api_key="icsmog-demo-key",
            role="analyst",
            is_active=True,
            created_by="bootstrap",
        )
        self.upsert_operator_account(
            username="admin",
            api_key="icsmog-admin-key",
            role="admin",
            is_active=True,
            created_by="bootstrap",
        )


def _parse_timestamp(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value)


def _hash_api_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def _open_connection(db_path: Path):
    with closing(sqlite3.connect(db_path)) as connection, connection:
        yield connection
