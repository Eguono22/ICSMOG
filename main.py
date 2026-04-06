"""
ICSMOG - Intelligent Computer Systems for Monitoring Organizations.

Main entry point that initializes all monitoring subsystems and demonstrates
their capabilities.
"""

from __future__ import annotations

import datetime

from src.business import BusinessIntelligence, EnterpriseResourcePlanning
from src.business.bi import ChartType, DataSet, Report
from src.business.erp import BusinessProcess, Department, ProcessStatus
from src.customer import CustomerRelationshipManagement, SentimentAnalyzer
from src.customer.crm import Customer, CustomerStage, Interaction, InteractionType
from src.customer.sentiment import DataSource, SocialPost
from src.cybersecurity import (
    IntrusionDetectionSystem,
    IntrusionPreventionSystem,
    SecurityInformationEventManagement,
)
from src.cybersecurity.ids_ips import NetworkEvent
from src.cybersecurity.siem import EventCategory, EventSeverity, SecurityEvent
from src.infrastructure import BuildingManagementSystem, IoTSensor, IoTSensorNetwork
from src.infrastructure.bms import BuildingSystem, OperationalStatus, SystemType
from src.infrastructure.iot_sensors import SensorType
from src.maintenance import PredictiveMaintenanceSystem, SCADASystem
from src.maintenance.predictive import Machine, SensorData
from src.maintenance.scada import PLCController, ProcessVariable
from src.workforce import WorkflowManagement, WorkforceAnalytics
from src.workforce.analytics import EmployeeMetrics
from src.workforce.workflow import Priority, Task, TaskStatus


def demo_cybersecurity() -> None:
    print("\n=== 1. Network & Cybersecurity Monitoring ===")

    # IDS/IPS
    ips = IntrusionPreventionSystem()
    normal_event = NetworkEvent(source_ip="192.168.1.10", destination_ip="10.0.0.1", port=80, protocol="HTTP", payload_size=512)
    suspicious_event = NetworkEvent(source_ip="203.0.113.5", destination_ip="10.0.0.1", port=22, protocol="SSH", payload_size=256)
    ips.analyze_event(normal_event)
    alert = ips.analyze_event(suspicious_event)
    print(f"  IPS alert: {alert.description if alert else 'None'}")
    print(f"  Auto-blocked IPs: {ips.auto_blocked_ips}")

    # SIEM
    siem = SecurityInformationEventManagement()
    for _ in range(5):
        siem.ingest_event(SecurityEvent(
            source="auth-service",
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.ERROR,
            message="Login failed",
        ))
    print(f"  SIEM dashboard: {siem.get_dashboard()}")


def demo_business() -> None:
    print("\n=== 2. Business Performance Monitoring ===")

    # ERP
    erp = EnterpriseResourcePlanning(organization="Acme Corp")
    proc = BusinessProcess(process_id="P001", name="Monthly Payroll", department=Department.HR)
    proc.start()
    erp.register_process(proc)
    erp.update_kpi("P001", "processed_employees", 250)
    print(f"  ERP dashboard: {erp.get_dashboard()}")

    # BI
    bi = BusinessIntelligence()
    ds = DataSet(name="sales", columns=["region", "revenue"])
    for region, revenue in [("North", 120000), ("South", 95000), ("East", 140000)]:
        ds.add_row({"region": region, "revenue": revenue})
    bi.register_dataset(ds)
    report = Report(title="Revenue by Region", dataset=ds, chart_type=ChartType.BAR, x_axis="region", y_axis="revenue")
    bi.create_report(report)
    print(f"  BI stats: {report.summary_stats()}")


def demo_infrastructure() -> None:
    print("\n=== 3. Environmental & Infrastructure Monitoring ===")

    # IoT
    network = IoTSensorNetwork(network_id="HQ-Floor1")
    temp_sensor = IoTSensor("T-001", SensorType.TEMPERATURE, "°C", "Server Room", min_threshold=18.0, max_threshold=28.0)
    network.register_sensor(temp_sensor)
    alert = network.record("T-001", 32.5)
    print(f"  IoT alert: {alert.message if alert else 'None'}")

    # BMS
    bms = BuildingManagementSystem("HQ Building")
    hvac = BuildingSystem("HVAC-01", SystemType.HVAC, "Floor 1")
    hvac.set_status(OperationalStatus.RUNNING)
    hvac.update_setting("temperature_setpoint", 22.0)
    bms.register_system(hvac)
    print(f"  BMS dashboard: {bms.get_dashboard()}")


def demo_workforce() -> None:
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
    print(f"  Workforce dashboard: {analytics.get_dashboard()}")

    # Workflow
    wf = WorkflowManagement("ICSMOG Dev")
    task = Task("T-001", "Implement IDS module", "Build IDS/IPS", assignee="E001",
                priority=Priority.HIGH, status=TaskStatus.IN_PROGRESS,
                due_date=datetime.date.today() + datetime.timedelta(days=7))
    wf.add_task(task)
    wf.transition_task("T-001", TaskStatus.DONE)
    print(f"  Workflow dashboard: {wf.get_dashboard()}")


def demo_maintenance() -> None:
    print("\n=== 5. Predictive Maintenance & Operational Monitoring ===")

    # Predictive maintenance
    pms = PredictiveMaintenanceSystem("Factory A")
    machine = Machine("M-001", "CNC Mill", normal_temp_range=(20.0, 60.0))
    pms.register_machine(machine)
    data = SensorData(machine_id="M-001", temperature=85.0, vibration=3.0, pressure=5.0, rpm=1500.0)
    alert = pms.ingest_sensor_data(data)
    print(f"  Predictive alert: {alert.description if alert else 'None'}")

    # SCADA
    scada = SCADASystem("Plant 1")
    plc = PLCController("PLC-01", "Boiler Control")
    pv = ProcessVariable(tag="TEMP", description="Boiler Temperature", value=100.0, unit="°C", low_limit=80.0, high_limit=120.0)
    plc.register_variable(pv)
    scada.register_plc(plc)
    alarm = scada.update("PLC-01", "TEMP", 135.0)
    print(f"  SCADA alarm: {alarm.message if alarm else 'None'}")


def demo_customer() -> None:
    print("\n=== 6. Customer & Market Monitoring ===")

    # CRM
    crm = CustomerRelationshipManagement("Acme Corp")
    customer = Customer("C-001", "Jane Doe", "jane@example.com", stage=CustomerStage.PROSPECT, account_value=50000.0)
    crm.add_customer(customer)
    crm.log_interaction(Interaction("C-001", InteractionType.MEETING, "Demo call", "sales_rep_1"))
    print(f"  CRM dashboard: {crm.get_dashboard()}")

    # Sentiment
    analyzer = SentimentAnalyzer("Acme Corp")
    posts = [
        SocialPost("P1", DataSource.TWITTER, "This product is amazing and excellent!", "user1", "product"),
        SocialPost("P2", DataSource.REVIEWS, "Terrible experience, product is broken and awful", "user2", "product"),
        SocialPost("P3", DataSource.NEWS, "Company announces great new features", "news_bot", "company"),
    ]
    analyzer.analyze_posts(posts)
    print(f"  Sentiment dashboard: {analyzer.get_dashboard()}")


def main() -> None:
    print("ICSMOG - Intelligent Computer Systems for Monitoring Organizations")
    print("=" * 65)
    demo_cybersecurity()
    demo_business()
    demo_infrastructure()
    demo_workforce()
    demo_maintenance()
    demo_customer()
    print("\nAll monitoring systems initialized successfully.")


if __name__ == "__main__":
    main()
