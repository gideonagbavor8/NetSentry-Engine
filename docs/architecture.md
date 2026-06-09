# NetSentry Engine Architecture

## Components

Capture Agent Client:

- Uses Scapy to sniff live network packets.
- Extracts frame, IPv4, TCP, UDP, port, and raw payload text fragments.
- Serializes telemetry as JSON.
- Sends each JSON object over a persistent TCP socket with a trailing newline delimiter.

Monitoring Dashboard Server:

- Opens a TCP listener on a local monitoring port.
- Accepts one or more capture agent connections.
- Buffers incoming bytes and splits complete messages on `\n`.
- Parses JSON frames and prints real-time traffic statistics.

## Stream Framing Rule

TCP is a byte stream, so one `recv()` call may contain a partial JSON object, one complete JSON object, or multiple JSON objects joined together. NetSentry Engine uses newline-delimited JSON so the server can safely accumulate bytes until a full frame is available.

## Privilege Requirement

Live packet capture normally requires administrator privileges on Windows or root privileges on Linux and macOS. The capture agent must check for this before starting Scapy sniffing so the user receives a clean error instead of a confusing low-level socket failure.
