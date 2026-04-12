"""
ICSMOG - Intelligent Computer Systems for Monitoring Organizations.

Main entry point that initializes all monitoring subsystems and demonstrates
their capabilities.
"""

from __future__ import annotations

import argparse
import datetime
import json
from typing import Any, Callable, Dict

from src.business import BusinessIntelligence, EnterpriseResourcePlanning
from src.business.bi import ChartType, DataSet, Report
from src.business.erp import BusinessProcess, Department
from src.customer import CustomerRelationshipManagement, SentimentAnalyzer
from src.customer.crm import Customer, CustomerStage, Interaction, InteractionType
from src.customer.sentiment import DataSource, SocialPost
from src.infrastructure import BuildingManagementSystem, IoTSensor, IoTSensorNetwork
from src.infrastructure.bms import BuildingSystem, OperationalStatus, SystemType
from src.infrastructure.iot_sensors import SensorType
from src.maintenance import PredictiveMaintenanceSystem, SCADASystem
from src.maintenance.predictive import Machine, SensorData
from src.maintenance.scada import PLCController, ProcessVariable
from src.api import run_cybersecurity_api_server
from src.ingestion import run_watch_directory_loop, scan_watch_directory_once
from src.services import run_sample_cybersecurity_scenario
from src.storage import CybersecurityEventStore
from src.services.cybersecurity import CybersecurityMonitoringService
from src.workforce import WorkflowManagement, WorkforceAnalytics
from src.workforce.analytics import EmployeeMetrics
from src.workforce.workflow import Priority, Task, TaskStatus


def demo_cybersecurity(verbose: bool = True) -> Dict[str, Any]:
    return run_sample_cybersecurity_scenario(verbose=verbose)


def demo_business(verbose: bool = True) -> Dict[str, Any]:
    if verbose:
        print("\n=== 2. Business Performance Monitoring ===")

    # ERP
    erp = EnterpriseResourcePlanning(organization="Acme Corp")
    proc = BusinessProcess(process_id="P001", name="Monthly Payroll", department=Department.HR)
    proc.start()
    erp.register_process(proc)
    erp.update_kpi("P001", "processed_employees", 250)
    erp_dashboard = erp.get_dashboard()
    if verbose:
        print(f"  ERP dashboard: {erp_dashboard}")

    # BI
    bi = BusinessIntelligence()
    ds = DataSet(name="sales", columns=["region", "revenue"])
    for region, revenue in [("North", 120000), ("South", 95000), ("East", 140000)]:
        ds.add_row({"region": region, "revenue": revenue})
    bi.register_dataset(ds)
    report = Report(title="Revenue by Region", dataset=ds, chart_type=ChartType.BAR, x_axis="region", y_axis="revenue")
    bi.create_report(report)
    bi_stats = report.summary_stats()
    if verbose:
        print(f"  BI stats: {bi_stats}")

    return {
        "erp_dashboard": erp_dashboard,
        "bi_dashboard": bi.get_dashboard(),
        "bi_stats": bi_stats,
    }


def demo_infrastructure(verbose: bool = True) -> Dict[str, Any]:
    if verbose:
        print("\n=== 3. Environmental & Infrastructure Monitoring ===")

    # IoT
    network = IoTSensorNetwork(network_id="HQ-Floor1")
    temp_sensor = IoTSensor("T-001", SensorType.TEMPERATURE, "°C", "Server Room", min_threshold=18.0, max_threshold=28.0)
    network.register_sensor(temp_sensor)
    alert = network.record("T-001", 32.5)
    if verbose:
        print(f"  IoT alert: {alert.message if alert else 'None'}")

    # BMS
    bms = BuildingManagementSystem("HQ Building")
    hvac = BuildingSystem("HVAC-01", SystemType.HVAC, "Floor 1")
    hvac.set_status(OperationalStatus.RUNNING)
    hvac.update_setting("temperature_setpoint", 22.0)
    bms.register_system(hvac)
    bms_dashboard = bms.get_dashboard()
    if verbose:
        print(f"  BMS dashboard: {bms_dashboard}")

    return {
        "iot_alert": alert.message if alert else None,
        "iot_dashboard": network.get_dashboard(),
        "bms_dashboard": bms_dashboard,
    }


def demo_workforce(verbose: bool = True) -> Dict[str, Any]:
    if verbose:
        print("\n=== 4. Employee & Workflow Monitoring ===")

    # Workforce analytics
    analytics = WorkforceAnalytics("Acme Corp")
    for i in range(1, 4):
        analytics.add_employee(EmployeeMetrics(
            employee_id=f"E{i:03d}", name=f"Employee {i}", department="Engineering",
            role="Developer", performance_score=60 + i * 10, productivity_score=55 + i * 10,
            engagement_score=50 + i * 10, attendance_rate=0.95,
            tasks_completed=8 + i, tasks_assigned=10,
        ))
    workforce_dashboard = analytics.get_dashboard()
    if verbose:
        print(f"  Workforce dashboard: {workforce_dashboard}")

    # Workflow
    wf = WorkflowManagement("ICSMOG Dev")
    task = Task("T-001", "Implement IDS module", "Build IDS/IPS", assignee="E001",
                priority=Priority.HIGH, status=TaskStatus.IN_PROGRESS,
                due_date=datetime.date.today() + datetime.timedelta(days=7))
    wf.add_task(task)
    wf.transition_task("T-001", TaskStatus.DONE)
    workflow_dashboard = wf.get_dashboard()
    if verbose:
        print(f"  Workflow dashboard: {workflow_dashboard}")

    return {
        "workforce_dashboard": workforce_dashboard,
        "workflow_dashboard": workflow_dashboard,
    }


def demo_maintenance(verbose: bool = True) -> Dict[str, Any]:
    if verbose:
        print("\n=== 5. Predictive Maintenance & Operational Monitoring ===")

    # Predictive maintenance
    pms = PredictiveMaintenanceSystem("Factory A")
    machine = Machine("M-001", "CNC Mill", normal_temp_range=(20.0, 60.0))
    pms.register_machine(machine)
    data = SensorData(machine_id="M-001", temperature=85.0, vibration=3.0, pressure=5.0, rpm=1500.0)
    alert = pms.ingest_sensor_data(data)
    if verbose:
        print(f"  Predictive alert: {alert.description if alert else 'None'}")

    # SCADA
    scada = SCADASystem("Plant 1")
    plc = PLCController("PLC-01", "Boiler Control")
    pv = ProcessVariable(tag="TEMP", description="Boiler Temperature", value=100.0, unit="°C", low_limit=80.0, high_limit=120.0)
    plc.register_variable(pv)
    scada.register_plc(plc)
    alarm = scada.update("PLC-01", "TEMP", 135.0)
    if verbose:
        print(f"  SCADA alarm: {alarm.message if alarm else 'None'}")

    return {
        "predictive_alert": alert.description if alert else None,
        "predictive_dashboard": pms.get_dashboard(),
        "scada_alarm": alarm.message if alarm else None,
        "scada_dashboard": scada.get_dashboard(),
    }


def demo_customer(verbose: bool = True) -> Dict[str, Any]:
    if verbose:
        print("\n=== 6. Customer & Market Monitoring ===")

    # CRM
    crm = CustomerRelationshipManagement("Acme Corp")
    customer = Customer("C-001", "Jane Doe", "jane@example.com", stage=CustomerStage.PROSPECT, account_value=50000.0)
    crm.add_customer(customer)
    crm.log_interaction(Interaction("C-001", InteractionType.MEETING, "Demo call", "sales_rep_1"))
    crm_dashboard = crm.get_dashboard()
    if verbose:
        print(f"  CRM dashboard: {crm_dashboard}")

    # Sentiment
    analyzer = SentimentAnalyzer("Acme Corp")
    posts = [
        SocialPost("P1", DataSource.TWITTER, "This product is amazing and excellent!", "user1", "product"),
        SocialPost("P2", DataSource.REVIEWS, "Terrible experience, product is broken and awful", "user2", "product"),
        SocialPost("P3", DataSource.NEWS, "Company announces great new features", "news_bot", "company"),
    ]
    analyzer.analyze_posts(posts)
    sentiment_dashboard = analyzer.get_dashboard()
    if verbose:
        print(f"  Sentiment dashboard: {sentiment_dashboard}")

    return {
        "crm_dashboard": crm_dashboard,
        "sentiment_dashboard": sentiment_dashboard,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ICSMOG demo runner for organizational monitoring modules."
    )
    parser.add_argument(
        "--step",
        type=int,
        choices=[1, 2, 3, 4, 5, 6],
        help="Run a single module demo step (1-6). Omit to run all steps.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output demo results as JSON for automation workflows.",
    )
    parser.add_argument(
        "--serve-api",
        action="store_true",
        help="Run the minimal cybersecurity HTTP API server.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for the HTTP API server.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the HTTP API server.",
    )
    parser.add_argument(
        "--storage-path",
        default="data/cybersecurity.db",
        help="SQLite database path for persisted cybersecurity API events.",
    )
    parser.add_argument(
        "--watch-csv-dir",
        help="Watch directory with network/ and security/ subfolders for CSV imports.",
    )
    parser.add_argument(
        "--watch-once",
        action="store_true",
        help="Scan the watch CSV directory once and exit.",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=10,
        help="Polling interval for the watch CSV directory.",
    )
    args = parser.parse_args()

    step_map: Dict[int, Callable[[bool], Dict[str, Any]]] = {
        1: demo_cybersecurity,
        2: demo_business,
        3: demo_infrastructure,
        4: demo_workforce,
        5: demo_maintenance,
        6: demo_customer,
    }

    if args.serve_api:
        run_cybersecurity_api_server(
            host=args.host,
            port=args.port,
            storage_path=args.storage_path,
        )
        return

    if args.watch_csv_dir:
        service = CybersecurityMonitoringService(
            store=CybersecurityEventStore(args.storage_path)
        )
        if args.watch_once:
            summary = scan_watch_directory_once(service, args.watch_csv_dir)
            print(json.dumps(summary, indent=2))
            return
        run_watch_directory_loop(
            service=service,
            watch_dir=args.watch_csv_dir,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        return

    if args.json:
        if args.step:
            output = {"step": args.step, "result": step_map[args.step](verbose=False)}
            print(json.dumps(output, indent=2))
            return
        output = {
            "steps": {str(step): step_map[step](verbose=False) for step in range(1, 7)}
        }
        print(json.dumps(output, indent=2))
        return

    print("ICSMOG - Intelligent Computer Systems for Monitoring Organizations")
    print("=" * 65)
    if args.step:
        step_map[args.step](verbose=True)
        print(f"\nStep {args.step} demo completed successfully.")
        return

    for step in range(1, 7):
        step_map[step](verbose=True)
    print("\nAll monitoring systems initialized successfully.")


if __name__ == "__main__":
    main()
