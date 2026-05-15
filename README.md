# ICSMOG

**Intelligent Computer Systems for Monitoring Organizations**

ICSMOG is a Python cybersecurity monitoring application-in-progress for simulating and validating security workflows. The strongest current use case is **security monitoring for small teams**: detecting suspicious network activity, correlating authentication and security events, and demonstrating explainable response behavior from a single codebase.

The repository also includes supporting modules for business intelligence, infrastructure monitoring, workforce analytics, maintenance, and customer intelligence, but those should be treated as adjacent capabilities while the cybersecurity product surface matures.

## Why This Project

Many monitoring tools are either too narrow to show cross-domain visibility or too broad to evaluate quickly. ICSMOG is useful as a:

- learning and prototyping environment for monitoring systems
- foundation for building a focused security or operations product
- demo framework for alerting, dashboards, and event correlation workflows

## Current Positioning

Today, ICSMOG is best understood as a **local MVP for cybersecurity workflows**, not a finished production application.

What works well now:

- a runnable cybersecurity API and browser dashboard
- a one-command MVP demo path with bundled network and auth sample data
- JSON output for lightweight automation and testing
- persistent SQLite-backed cybersecurity event history through the API
- built-in cybersecurity dashboard served from the same API process
- local operator accounts with role-based access for protected workflows
- persistent operator audit trails for imports and alert lifecycle changes
- API and dashboard alert filtering by severity, status, IPs, protocol, port, and free-text search
- dedicated authentication event ingestion with explainable auth-focused correlation rules
- unit tests covering the existing domain modules

What is not built yet:

- real-time streaming ingestion
- a full multi-user operations dashboard
- external identity integration and session-based authentication
- production deployment workflow

## Primary Use Case

The clearest near-term product direction is **security monitoring for small teams**.

That means ICSMOG should gradually evolve toward:

- ingesting network and auth events
- detecting suspicious behavior with understandable rules
- correlating related incidents in a SIEM-style workflow
- surfacing alerts in a dashboard or API
- supporting lightweight automated response actions

## Project Structure

```text
ICSMOG/
|- main.py               # Entry point for CLI demos
|- requirements.txt      # Python dependencies
|- src/
|  |- cybersecurity/     # IDS, IPS, and SIEM
|  |- business/          # ERP and business intelligence
|  |- infrastructure/    # IoT sensors and building systems
|  |- workforce/         # Workforce analytics and workflow management
|  |- maintenance/       # Predictive maintenance and SCADA
|  `- customer/          # CRM and sentiment analysis
`- tests/                # Unit tests
```

## Modules

### Cybersecurity

**Path:** `src/cybersecurity`

This is the most product-ready area of the repository today.

| Class | Description |
|-------|-------------|
| `IntrusionDetectionSystem` | Flags suspicious traffic using blocklists, high-risk ports, and anomalous payload patterns. |
| `IntrusionPreventionSystem` | Extends detection with automatic blocking behavior for severe alerts. |
| `SecurityInformationEventManagement` | Aggregates security events, applies correlation rules, and summarizes incident activity. |

### Additional Domain Modules

These modules are available in the repo and useful for experimentation, but they currently support the project story rather than define it.

| Domain | Path | Purpose |
|-------|------|---------|
| Business | `src/business` | ERP process monitoring and business intelligence reporting |
| Infrastructure | `src/infrastructure` | IoT sensor alerts and building system monitoring |
| Workforce | `src/workforce` | Employee analytics and workflow tracking |
| Maintenance | `src/maintenance` | Predictive maintenance and SCADA-style monitoring |
| Customer | `src/customer` | CRM workflows and sentiment analysis |

## Installation

```bash
git clone https://github.com/Eguono22/ICSMOG.git
cd ICSMOG
pip install -r requirements.txt
```

## Start Here

If you want to evaluate ICSMOG as a product, start with the cybersecurity MVP flow instead of the full multi-domain demo:

```bash
python main.py --mvp-demo
```

Then open `http://127.0.0.1:8000/dashboard` and sign in with:

- `analyst-1` / `icsmog-demo-key`
- `admin` / `icsmog-admin-key`

The MVP demo preloads bundled network and authentication samples into an empty database so the dashboard opens with realistic alerts, auth history, and rule activity already present.

## Running

Recommended first run for product evaluation:

```bash
python main.py --mvp-demo
```

Run the cybersecurity API and dashboard without preloaded sample data:

```bash
python main.py --serve-api
```

Use a custom SQLite path if needed:

```bash
python main.py --mvp-demo --storage-path data/cybersecurity.db
```

Run the full multi-domain demo:

```bash
python main.py
```

Run only the cybersecurity step:

```bash
python main.py --step 1
```

Output JSON for automation workflows:

```bash
python main.py --json
```

Output JSON for a single step:

```bash
python main.py --step 1 --json
```

Scan a watch folder once for CSV files:

```bash
python main.py --watch-csv-dir examples/watch_inbox --watch-once
```

Continuously watch a folder for new CSV files:

```bash
python main.py --watch-csv-dir examples/watch_inbox --poll-interval-seconds 10
```

Expected watch-folder layout:

```text
watch_inbox/
|- network/
|  `- *.csv
|- security/
|  `- *.csv
`- auth/
   `- *.csv
```

Example endpoints:

- `GET /`
- `GET /dashboard`
- `GET /dashboard/alerts/<alert_id>`
- `GET /health`
- `GET /cybersecurity/dashboard`
- `GET /cybersecurity/alerts`
- `GET /cybersecurity/auth-events`
- `GET /cybersecurity/alerts/<alert_id>`
- `GET /cybersecurity/alerts/<alert_id>/investigation`
- `GET /cybersecurity/import-history`
- `GET /cybersecurity/audit-log`
- `GET /cybersecurity/me`
- `GET /cybersecurity/operators`
- `POST /cybersecurity/login`
- `POST /cybersecurity/logout`
- `POST /cybersecurity/import/scan-directory`
- `POST /cybersecurity/alerts/<alert_id>/acknowledge`
- `POST /cybersecurity/alerts/<alert_id>/resolve`
- `POST /cybersecurity/operators`
- `POST /cybersecurity/import/network-csv`
- `POST /cybersecurity/import/security-csv`
- `POST /cybersecurity/import/auth-csv`
- `POST /cybersecurity/import/auth-log`
- `POST /cybersecurity/network-events`
- `POST /cybersecurity/security-events`
- `POST /cybersecurity/auth-events`

CSV imports accept either `csv_path` or `csv_text`. Example:

```json
{
  "csv_path": "examples/network_events.csv"
}
```

The auth log connector accepts newline-delimited JSON via `log_path` or
`log_text`. Example:

```json
{
  "log_path": "examples/auth_log_export.ndjson"
}
```

Sample files are available at:

- `examples/network_events.csv`
- `examples/security_events.csv`
- `examples/auth_events.csv`
- `examples/auth_log_export.ndjson`

Authentication event payloads accept fields such as `source`, `username`,
`source_ip`, `auth_method`, `result`, optional `target_resource`,
`is_privileged`, and `failure_reason`. ICSMOG currently includes explainable
rules for repeated failures, disabled-account attempts, and privileged logins
from public IP space.
The auth log connector maps common nested export fields such as
`user.username`, `actor.name`, `client.ip`, `source.ip`, `auth.method`,
`authentication.result`, `target.resource`, and role lists containing
`admin`/`administrator` into that same auth event model.
Stored auth history can be queried through `GET /cybersecurity/auth-events`
using filters like `username`, `source_ip`, `auth_method`, `result`,
`target_resource`, `failure_reason`, `is_privileged`, `query`, and `limit`.

The watch-folder workflow records processed files in the SQLite database, so
already-imported CSVs are skipped after restart unless the file contents change.
Import history records both successful and failed CSV attempts so operators can
review what was accepted and what was rejected.
Protected operator actions require `X-Operator-Name` and `X-Operator-Key`
headers. The default bootstrap accounts are:

- `analyst-1` with key `icsmog-demo-key` and role `analyst`
- `admin` with key `icsmog-admin-key` and role `admin`

Analysts can import CSV data and acknowledge alerts. Admins can also resolve
alerts and manage operator accounts through the API or dashboard.

The browser dashboard now supports session-based sign-in through
`POST /cybersecurity/login` and `POST /cybersecurity/logout`, so operators do not
need to resend raw credentials on every protected action. Header-based
authentication still works for scripts and test automation.

For recurring feeds, operators can also trigger
`POST /cybersecurity/import/scan-directory` with a server-accessible
`directory_path`, `target` (`network`, `security`, or `auth`), and optional filename
`pattern` to import matching CSV files while skipping files that were already
processed.

## Example Direction

If you are evaluating ICSMOG as a future application, the most promising path is:

1. focus the product around cybersecurity monitoring
2. validate the `--mvp-demo` workflow with real small-team operators
3. refine the built-in dashboard into a more complete triage UI
4. add real connectors for logs, auth events, or CSV imports
5. harden deployment, identity, and operations workflows

## Roadmap

### Available Now

- cybersecurity API, dashboard, and persisted history
- MVP demo runner with bundled sample security data
- JSON-formatted output
- unit test coverage for domain behavior

### Next

- sharper onboarding and first-run conversion from repo to working demo
- better dashboard workflows for investigation and triage
- more realistic external connectors beyond CSV imports
- clearer packaging and deployment for repeatable evaluation environments

### Later

- external identity providers, session auth, and richer user management
- streaming or scheduled ingestion
- deployment and packaging improvements

## Testing

Run the test suite with:

```bash
pip install pytest
python -m pytest tests/ -v
```

## Contributing

For local development setup, linting, test commands, and pull request guidance, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
