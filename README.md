# ICSMOG

**Intelligent Computer Systems for Monitoring Organizations**

ICSMOG is a Python framework that simulates advanced organizational monitoring systems using artificial intelligence (AI), machine learning (ML), big data analytics, and automation. It tracks organizational performance, security posture, infrastructure health, workforce productivity, predictive maintenance, and customer intelligence — all from a single, unified codebase.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Modules](#modules)
  - [1. Network & Cybersecurity Monitoring](#1-network--cybersecurity-monitoring)
  - [2. Business Performance Monitoring](#2-business-performance-monitoring)
  - [3. Environmental & Infrastructure Monitoring](#3-environmental--infrastructure-monitoring)
  - [4. Employee & Workflow Monitoring](#4-employee--workflow-monitoring)
  - [5. Predictive Maintenance & Operational Monitoring](#5-predictive-maintenance--operational-monitoring)
  - [6. Customer & Market Monitoring](#6-customer--market-monitoring)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running](#running)
- [Testing](#testing)

---

## Overview

ICSMOG models six major monitoring domains found in modern enterprises. Each domain is implemented as an independent module under `src/`, exposing clean Python classes that can be instantiated, configured, and queried independently or together.

---

## Project Structure

```
ICSMOG/
├── main.py               # Entry point — runs a full demo of all modules
├── requirements.txt      # Python dependencies
├── src/
│   ├── cybersecurity/    # IDS, IPS, and SIEM
│   ├── business/         # ERP and Business Intelligence
│   ├── infrastructure/   # IoT sensors and Building Management System
│   ├── workforce/        # Workforce analytics and workflow management
│   ├── maintenance/      # Predictive maintenance and SCADA
│   └── customer/         # CRM and sentiment analysis
└── tests/                # Unit tests for all modules
```

---

## Modules

### 1. Network & Cybersecurity Monitoring

**Path:** `src/cybersecurity`

Monitors network traffic and security events to detect and respond to threats in real time.

| Class | Description |
|-------|-------------|
| `IntrusionDetectionSystem` | Rule-based and anomaly-based network intrusion detection. Flags traffic from blocklisted IPs, access on high-risk ports (SSH, RDP, etc.), and unusually large payloads. |
| `IntrusionPreventionSystem` | Extends the IDS with active prevention — automatically blocks source IPs that trigger `HIGH` or `CRITICAL` alerts. |
| `SecurityInformationEventManagement` | Aggregates security events from multiple sources, runs correlation rules (e.g. brute-force detection), and provides a unified security dashboard. |

---

### 2. Business Performance Monitoring

**Path:** `src/business`

Tracks core business processes and generates analytical reports from operational data.

| Class | Description |
|-------|-------------|
| `EnterpriseResourcePlanning` | Monitors business processes across Finance, HR, Procurement, Supply Chain, and Operations departments. Tracks KPIs per process and produces a live dashboard. |
| `BusinessIntelligence` | Registers datasets, creates chart-backed reports (bar, line, pie, scatter), and computes summary statistics for data-driven decision making. |

---

### 3. Environmental & Infrastructure Monitoring

**Path:** `src/infrastructure`

Monitors physical environments and building systems through IoT sensors and a central Building Management System.

| Class | Description |
|-------|-------------|
| `IoTSensor` | Represents an individual sensor (temperature, humidity, vibration, air quality, pressure, motion) with configurable alert thresholds. |
| `IoTSensorNetwork` | Manages a network of sensors, records readings, and raises threshold alerts automatically. |
| `BuildingManagementSystem` | Oversees building systems (HVAC, lighting, security, fire safety, elevators, power) and tracks operational status and settings. |

---

### 4. Employee & Workflow Monitoring

**Path:** `src/workforce`

Tracks employee performance and manages task-based project workflows.

| Class | Description |
|-------|-------------|
| `WorkforceAnalytics` | Records per-employee metrics (performance, productivity, engagement, attendance, task completion) and surfaces organisation-wide summaries. |
| `WorkflowManagement` | Manages tasks with priorities and statuses, supports lifecycle transitions (e.g. `TODO → IN_PROGRESS → DONE`), and reports team-level workflow health. |

---

### 5. Predictive Maintenance & Operational Monitoring

**Path:** `src/maintenance`

Uses sensor telemetry to predict equipment failures and monitors industrial control systems.

| Class | Description |
|-------|-------------|
| `PredictiveMaintenanceSystem` | Registers machines, ingests sensor data (temperature, vibration, pressure, RPM), and raises alerts when readings fall outside safe operating ranges. |
| `SCADASystem` | Manages PLC controllers and process variables. Triggers alarms when a process variable exceeds its configured low/high limits. |

---

### 6. Customer & Market Monitoring

**Path:** `src/customer`

Manages customer relationships and analyses public sentiment about the organisation.

| Class | Description |
|-------|-------------|
| `CustomerRelationshipManagement` | Stores customer records with lifecycle stages (prospect → active → churned), logs interactions (meetings, emails, calls, demos), and tracks account value. |
| `SentimentAnalyzer` | Analyses social media posts, reviews, and news articles using keyword-based sentiment scoring and aggregates results into a brand health dashboard. |

---

## Requirements

- Python 3.9+
- [numpy](https://numpy.org/) >= 1.24.0
- [scikit-learn](https://scikit-learn.org/) >= 1.3.0
- [pandas](https://pandas.pydata.org/) >= 2.0.0

---

## Installation

```bash
git clone https://github.com/Eguono22/ICSMOG.git
cd ICSMOG
pip install -r requirements.txt
```

---

## Running

Execute the full demo, which initialises all six monitoring subsystems and prints a live summary for each:

```bash
python main.py
```

Run only a specific step (for example, Step 1 - Network & Cybersecurity Monitoring):

```bash
python main.py --step 1
```

Output machine-readable JSON for all steps:

```bash
python main.py --json
```

Output JSON for a single step:

```bash
python main.py --step 2 --json
```

Example JSON payload for a single step:

```json
{
  "step": 2,
  "result": {
    "erp_dashboard": {
      "organization": "Acme Corp",
      "total_processes": 1,
      "status_breakdown": {
        "pending": 0,
        "in_progress": 1,
        "completed": 0,
        "failed": 0
      },
      "department_breakdown": {
        "finance": 0,
        "hr": 1,
        "procurement": 0,
        "supply_chain": 0,
        "operations": 0
      }
    },
    "bi_dashboard": {
      "platform": "ICSMOG-BI",
      "datasets": 1,
      "reports": 1,
      "report_titles": [
        "Revenue by Region"
      ]
    },
    "bi_stats": {
      "count": 3,
      "mean": 118333.33333333333,
      "median": 120000,
      "stdev": 22546.248764114473
    }
  }
}
```

---

## Testing

Run the full test suite with:

```bash
pip install pytest
python -m pytest tests/ -v
```
