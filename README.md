# NetSentry Engine

NetSentry Engine is an isolated network traffic monitoring and packet analysis console for the Week 5 and Week 6 Applied Programming module.

The project is split into two Python components:

1. Capture Agent Client: sniffs live packet metadata with Scapy and streams newline-delimited JSON telemetry to the dashboard server.
2. Monitoring Dashboard Server: accepts TCP client streams, splits incoming frames on `\n`, parses JSON safely, and prints real-time traffic statistics.

## Recommended Layout

```text
.
|-- README.md
|-- pyproject.toml
|-- requirements.txt
|-- docs/
|   `-- architecture.md
|-- src/
|   `-- netsentry/
|       |-- __init__.py
|       |-- agent/
|       |   |-- __init__.py
|       |   `-- capture_agent.py
|       |-- common/
|       |   |-- __init__.py
|       |   `-- privileges.py
|       `-- server/
|           |-- __init__.py
|           `-- dashboard_server.py
`-- tests/
    `-- __init__.py
```

## Install Dependencies

Create and activate a virtual environment, then install the runtime dependency:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Scapy usually requires administrator or root privileges to capture traffic from a live network interface.

## Initial Commands

Start the dashboard server:

```powershell
python -m netsentry.server.dashboard_server
```

Start the capture agent from an elevated terminal:

```powershell
python -m netsentry.agent.capture_agent
```
