# Overview

As a software engineer, I am developing the NetSentry Engine to deepen my understanding of low-level systems communication, concurrent programming, and automated security auditing. This project allows me to explore how network bytes are transmitted across a transport medium, how data payloads are safely parsed and sanitized under real-world constraints, and how to implement a high-performance network pipeline without disrupting production environments.

The NetSentry Engine is an isolated, distributed network traffic monitoring and packet analysis platform. It is architected as two decoupled Python services: a Capture Agent Client that sniffs real-time network traffic and a centralized Monitoring Dashboard Server that aggregates data streams. The agent passively captures live Layer 3 and Layer 4 packet data, formats the metadata into predictable schemas, and pipes them over a TCP socket loopback. The server processes these high-velocity telemetry feeds, separates merging frames using custom string structures, and computes real-time performance and protocol metrics.

My purpose for creating this software is to develop an optimization toolkit for network baseline visibility and security telemetry processing. By engineering a custom communication stream from scratch, I can practice solving common socket issues like buffer aggregation and handle multi-threaded client execution. Additionally, it gives me a practical tool to analyze local protocol distribution, audit connection metrics, and implement payload sanitization layers that flag compliance alerts safely.

[Software Demo Video] https://www.loom.com/share/3dc7a96c409a4c90a95222cd7543a36b

# Development Environment

To develop this software, I utilized the following tools:
* **Visual Studio Code (VS Code):** Used as the primary Integrated Development Environment (IDE) with integrated administrative split terminals for side-by-side component monitoring.
* **Git and GitHub:** Employed for localized version tracking and public source repository hosting.
* **PowerShell (Administrator Mode):** Utilized to grant the execution scripts elevated privileges for direct network interface driver interactions.

This project is authored entirely in the **Python** programming language, leveraging the following packages and native modules:
* **Scapy:** Used to interact directly with the network interface card for live packet capture, parsing, and dissection.
* **Sockets & Threading (Standard Library):** Leveraged to build the non-blocking concurrent TCP pipeline between the agent and the server.
* **JSON (Standard Library):** Utilized for structured cross-process data serialization and frame exchange.

### Useful Websites
* [Scapy Documentation](https://scapy.readthedocs.io/)
* [Python Socket Programming Guide (Real Python)](https://realpython.com/python-sockets/)
* [Npcap Windows Packet Capture Library](https://npcap.com/)

I used the following commands to set up my localized runtime environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .