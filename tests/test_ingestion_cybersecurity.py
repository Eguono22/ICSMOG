"""Tests for watch-folder cybersecurity ingestion workflows."""

import tempfile
from pathlib import Path

from src.ingestion.cybersecurity import scan_watch_directory_once
from src.services.cybersecurity import CybersecurityMonitoringService
from src.storage import CybersecurityEventStore


def test_scan_watch_directory_once_imports_new_network_and_security_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        watch_root = Path(temp_dir) / "watch"
        network_dir = watch_root / "network"
        security_dir = watch_root / "security"
        network_dir.mkdir(parents=True)
        security_dir.mkdir(parents=True)
        (network_dir / "batch-1.csv").write_text(
            "source_ip,destination_ip,port,protocol,payload_size\n"
            "198.51.100.71,10.0.0.71,22,SSH,100\n",
            encoding="utf-8",
        )
        (security_dir / "batch-1.csv").write_text(
            "source,category,severity,message\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n",
            encoding="utf-8",
        )
        service = CybersecurityMonitoringService(
            store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        )

        summary = scan_watch_directory_once(service, str(watch_root))
        dashboard = service.get_dashboard()

    assert summary["imported_files"] == 2
    assert len(summary["network"]["processed_files"]) == 1
    assert len(summary["security"]["processed_files"]) == 1
    assert dashboard["ips"]["total_events"] == 1
    assert dashboard["siem"]["triggered_rules"] == 1


def test_scan_watch_directory_once_skips_already_processed_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        watch_root = Path(temp_dir) / "watch"
        network_dir = watch_root / "network"
        network_dir.mkdir(parents=True)
        csv_file = network_dir / "batch-1.csv"
        csv_file.write_text(
            "source_ip,destination_ip,port,protocol,payload_size\n"
            "198.51.100.72,10.0.0.72,22,SSH,100\n",
            encoding="utf-8",
        )
        service = CybersecurityMonitoringService(
            store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        )

        first_summary = scan_watch_directory_once(service, str(watch_root))
        second_summary = scan_watch_directory_once(service, str(watch_root))

    assert first_summary["imported_files"] == 1
    assert second_summary["imported_files"] == 0
    assert len(second_summary["network"]["skipped_files"]) == 1


def test_scan_watch_directory_once_reports_failed_files_and_continues():
    with tempfile.TemporaryDirectory() as temp_dir:
        watch_root = Path(temp_dir) / "watch"
        network_dir = watch_root / "network"
        security_dir = watch_root / "security"
        network_dir.mkdir(parents=True)
        security_dir.mkdir(parents=True)
        (network_dir / "bad.csv").write_text(
            "source_ip,destination_ip,protocol,payload_size\n"
            "198.51.100.73,10.0.0.73,SSH,100\n",
            encoding="utf-8",
        )
        (security_dir / "good.csv").write_text(
            "source,category,severity,message\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n"
            "auth-service,authentication,error,Login failed\n",
            encoding="utf-8",
        )
        service = CybersecurityMonitoringService(
            store=CybersecurityEventStore(f"{temp_dir}/cybersecurity.db")
        )

        summary = scan_watch_directory_once(service, str(watch_root))
        history = service.get_import_history(limit=5)

    assert summary["imported_files"] == 1
    assert len(summary["network"]["failed_files"]) == 1
    assert len(summary["security"]["processed_files"]) == 1
    assert history[0]["status"] in {"success", "failed"}
    assert any(entry["status"] == "failed" for entry in history)
