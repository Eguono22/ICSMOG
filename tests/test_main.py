"""CLI smoke tests for the demo runner."""

import json

import pytest

import main


class TestMainCLI:
    def test_step_json_outputs_expected_shape(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "sys.argv",
            ["main.py", "--step", "2", "--json"],
        )

        main.main()

        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert payload["step"] == 2
        assert payload["result"]["erp_dashboard"]["organization"] == "Acme Corp"
        assert payload["result"]["bi_dashboard"]["reports"] == 1
        assert payload["result"]["bi_stats"]["count"] == 3

    def test_json_outputs_all_steps(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["main.py", "--json"])

        main.main()

        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert sorted(payload["steps"].keys()) == ["1", "2", "3", "4", "5", "6"]
        assert "ips" in payload["steps"]["1"]
        assert "workflow_dashboard" in payload["steps"]["4"]
        assert "sentiment_dashboard" in payload["steps"]["6"]

    def test_invalid_step_is_rejected(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["main.py", "--step", "7"])

        with pytest.raises(SystemExit) as exc_info:
            main.main()

        assert exc_info.value.code == 2

    def test_mvp_demo_starts_seeded_api_server(self, monkeypatch):
        captured = {}

        def fake_run_server(**kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(
            "sys.argv",
            ["main.py", "--mvp-demo", "--host", "0.0.0.0", "--port", "9000"],
        )
        monkeypatch.setattr(main, "run_cybersecurity_api_server", fake_run_server)

        main.main()

        assert captured == {
            "host": "0.0.0.0",
            "port": 9000,
            "storage_path": "data/cybersecurity.db",
            "seed_demo_data": True,
        }
