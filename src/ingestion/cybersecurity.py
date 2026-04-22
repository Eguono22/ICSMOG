"""Watch-folder ingestion workflows for cybersecurity CSV feeds."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List

from src.services.cybersecurity import CybersecurityMonitoringService


def scan_watch_directory_once(
    service: CybersecurityMonitoringService,
    watch_dir: str,
) -> Dict[str, Any]:
    """Scan a watch directory once and import any new CSV files."""
    root = Path(watch_dir)
    network_dir = root / "network"
    security_dir = root / "security"
    auth_dir = root / "auth"
    network_dir.mkdir(parents=True, exist_ok=True)
    security_dir.mkdir(parents=True, exist_ok=True)
    auth_dir.mkdir(parents=True, exist_ok=True)

    imported_network_files = _import_pending_files(
        service=service,
        directory=network_dir,
        import_type="network_csv",
        importer=service.import_network_csv,
    )
    imported_security_files = _import_pending_files(
        service=service,
        directory=security_dir,
        import_type="security_csv",
        importer=service.import_security_csv,
    )
    imported_auth_files = _import_pending_files(
        service=service,
        directory=auth_dir,
        import_type="auth_csv",
        importer=service.import_auth_csv,
    )

    return {
        "watch_dir": str(root),
        "network": imported_network_files,
        "security": imported_security_files,
        "auth": imported_auth_files,
        "imported_files": (
            len(imported_network_files["processed_files"])
            + len(imported_security_files["processed_files"])
            + len(imported_auth_files["processed_files"])
        ),
    }


def run_watch_directory_loop(
    service: CybersecurityMonitoringService,
    watch_dir: str,
    poll_interval_seconds: int = 10,
) -> None:
    """Continuously poll a watch directory for new CSV files."""
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be greater than 0")

    print(f"Watching CSV inbox at {watch_dir}")
    print("Expected folders: network/, security/, and auth/")
    print(f"Polling every {poll_interval_seconds} second(s). Press Ctrl+C to stop.")

    try:
        while True:
            summary = scan_watch_directory_once(service, watch_dir)
            if summary["imported_files"]:
                print(
                    "Imported "
                    f"{summary['imported_files']} file(s): "
                    f"{summary['network']['processed_files']} network, "
                    f"{summary['security']['processed_files']} security, "
                    f"{summary['auth']['processed_files']} auth"
                )
            if (
                summary["network"]["failed_files"]
                or summary["security"]["failed_files"]
                or summary["auth"]["failed_files"]
            ):
                print(
                    "Import failures detected: "
                    f"{summary['network']['failed_files']} network, "
                    f"{summary['security']['failed_files']} security, "
                    f"{summary['auth']['failed_files']} auth"
                )
            time.sleep(poll_interval_seconds)
    except KeyboardInterrupt:
        print("\nStopping CSV watch loop.")


def _import_pending_files(
    service: CybersecurityMonitoringService,
    directory: Path,
    import_type: str,
    importer: Any,
) -> Dict[str, List[str]]:
    processed_files: List[str] = []
    skipped_files: List[str] = []
    failed_files: List[str] = []

    for path in sorted(directory.glob("*.csv")):
        file_key = _build_file_key(path)
        if service.store is not None and service.store.has_processed_import(file_key):
            skipped_files.append(str(path))
            continue

        try:
            importer({"csv_path": str(path)})
        except ValueError as exc:
            failed_files.append(f"{path}: {exc}")
            continue
        if service.store is not None:
            service.store.mark_processed_import(
                file_key=file_key,
                file_path=str(path),
                import_type=import_type,
            )
        processed_files.append(str(path))

    return {
        "processed_files": processed_files,
        "skipped_files": skipped_files,
        "failed_files": failed_files,
    }


def _build_file_key(path: Path) -> str:
    stat = path.stat()
    fingerprint = "|".join(
        [
            str(path.resolve()),
            str(stat.st_mtime_ns),
            str(stat.st_size),
        ]
    )
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()
