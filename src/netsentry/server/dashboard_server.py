"""Threaded TCP socket listener for the NetSentry monitoring dashboard."""

from __future__ import annotations

import argparse
import json
import socket
import threading
from collections import Counter
from typing import Any

from netsentry.common.schemas import JSON_FRAME_DELIMITER, STREAM_ENCODING


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
RECV_BUFFER_SIZE = 4096
SOCKET_TIMEOUT_SECONDS = 1.0
MAX_PENDING_BUFFER_BYTES = 1_000_000
FRAME_DELIMITER_BYTES = JSON_FRAME_DELIMITER.encode(STREAM_ENCODING)


class DashboardStats:
    """Thread-safe counters for packets received by the dashboard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_packets = 0
        self._protocol_counts: Counter[str] = Counter()
        self._compliance_counts: Counter[str] = Counter()

    def record_packet(self, packet_metadata: dict[str, Any]) -> int:
        """Update dashboard counters and return the new total packet count."""
        protocol_type = str(packet_metadata.get("protocol_type") or "Other")
        compliance_flags = packet_metadata.get("compliance_flags") or []

        with self._lock:
            self._total_packets += 1
            self._protocol_counts[protocol_type] += 1

            for flag in compliance_flags:
                self._compliance_counts[str(flag)] += 1

            return self._total_packets

    def snapshot(self) -> dict[str, Any]:
        """Return a stable copy of the current dashboard counters."""
        with self._lock:
            return {
                "total_packets": self._total_packets,
                "protocol_counts": dict(self._protocol_counts),
                "compliance_counts": dict(self._compliance_counts),
            }


def split_stream_buffer(receive_buffer: bytes) -> tuple[list[bytes], bytes]:
    """Split complete JSON frames from a TCP byte buffer.

    TCP is a stream, so one recv call can contain partial JSON, one JSON
    message, or multiple JSON messages. The trailing newline marks each
    complete telemetry frame.

    Why ``maxsplit=1``:
        ``bytes.split`` without a limit would consume the *entire* buffer in
        one call and discard any partial frame at the tail.  ``maxsplit=1``
        peels off exactly one frame per iteration so the loop can stop as soon
        as no complete delimiter is found, leaving the incomplete tail intact
        for the next ``recv`` call.

    Why ``.strip()`` is only a truthiness guard:
        The unsplit ``frame_bytes`` (not the stripped copy) is appended to
        ``complete_frames`` so that ``json.loads`` sees exactly the bytes that
        arrived off the wire.  ``json.loads`` already ignores surrounding ASCII
        whitespace, so no information is lost.  The truthiness check simply
        discards frames that are entirely whitespace (e.g. a double-newline
        sent by a misbehaving client) without logging a spurious JSON error.
    """
    complete_frames: list[bytes] = []

    while FRAME_DELIMITER_BYTES in receive_buffer:
        # maxsplit=1: isolate the first complete frame and keep the rest of
        # the buffer (which may contain more frames or a partial frame) intact.
        frame_bytes, receive_buffer = receive_buffer.split(FRAME_DELIMITER_BYTES, 1)

        # Skip frames that are blank (e.g. consecutive delimiters); pass the
        # original unsplit bytes so json.loads receives unmodified wire data.
        if frame_bytes.strip():
            complete_frames.append(frame_bytes)

    return complete_frames, receive_buffer


def deserialize_packet_frame(frame_bytes: bytes, client_label: str) -> dict[str, Any] | None:
    """Decode one newline-delimited JSON packet frame into a dictionary."""
    try:
        frame_text = frame_bytes.decode(STREAM_ENCODING)
        packet_metadata = json.loads(frame_text)
    except UnicodeDecodeError as error:
        print(f"[server] Dropped non UTF-8 frame from {client_label}: {error}")
        return None
    except json.JSONDecodeError as error:
        print(f"[server] Dropped malformed JSON frame from {client_label}: {error}")
        return None

    if not isinstance(packet_metadata, dict):
        print(f"[server] Dropped JSON frame from {client_label}: expected object")
        return None

    return packet_metadata


def format_endpoint(ip_address: Any, port_number: Any) -> str:
    """Format an IP and optional port for console output."""
    if ip_address and port_number is not None:
        return f"{ip_address}:{port_number}"

    return str(ip_address or "unknown")


def format_packet_summary(packet_metadata: dict[str, Any], total_packets: int) -> str:
    """Build a compact console summary for one captured packet."""
    protocol_type = str(packet_metadata.get("protocol_type") or "Other")
    source_endpoint = format_endpoint(
        packet_metadata.get("source_ip"),
        packet_metadata.get("source_port"),
    )
    destination_endpoint = format_endpoint(
        packet_metadata.get("destination_ip"),
        packet_metadata.get("destination_port"),
    )
    tcp_flags = packet_metadata.get("tcp_flags") or "none"
    payload_preview = packet_metadata.get("payload_preview") or ""
    compliance_flags = packet_metadata.get("compliance_flags") or []
    compliance_text = ",".join(str(flag) for flag in compliance_flags) or "none"

    return (
        f"[packet {total_packets}] protocol={protocol_type} "
        f"source={source_endpoint} destination={destination_endpoint} "
        f"tcp_flags={tcp_flags} compliance={compliance_text} "
        f"payload_preview={payload_preview}"
    )


def handle_client_connection(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    dashboard_stats: DashboardStats,
) -> None:
    """Read newline-delimited JSON telemetry from one capture agent."""
    client_label = f"{client_address[0]}:{client_address[1]}"
    receive_buffer = b""

    print(f"[server] Capture agent connected from {client_label}")

    try:
        with client_socket:
            client_socket.settimeout(SOCKET_TIMEOUT_SECONDS)

            while True:
                try:
                    data_chunk = client_socket.recv(RECV_BUFFER_SIZE)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError) as error:
                    # Covers both POSIX ECONNRESET and Windows WSAECONNABORTED (10053).
                    print(
                        f"[server] Connection abruptly closed by {client_label} "
                        f"({type(error).__name__})"
                    )
                    break
                except BrokenPipeError:
                    print(f"[server] Broken pipe while reading from {client_label}")
                    break
                except OSError as error:
                    print(f"[server] Socket read error from {client_label}: {error}")
                    break

                if not data_chunk:
                    print(f"[server] Capture agent disconnected from {client_label}")
                    break

                # Keep partial TCP data until a newline-delimited JSON frame is complete.
                receive_buffer += data_chunk

                if len(receive_buffer) > MAX_PENDING_BUFFER_BYTES:
                    print(f"[server] Dropped oversized pending buffer from {client_label}")
                    receive_buffer = b""
                    continue

                complete_frames, receive_buffer = split_stream_buffer(receive_buffer)

                for frame_bytes in complete_frames:
                    packet_metadata = deserialize_packet_frame(frame_bytes, client_label)
                    if packet_metadata is None:
                        continue

                    total_packets = dashboard_stats.record_packet(packet_metadata)
                    print(format_packet_summary(packet_metadata, total_packets))
    finally:
        if receive_buffer.strip():
            print(f"[server] Dropped incomplete frame from {client_label}")

        print(f"[server] Handler stopped for {client_label}")


def start_dashboard_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Start the dashboard listener and spawn handler threads for clients."""
    dashboard_stats = DashboardStats()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()
        server_socket.settimeout(SOCKET_TIMEOUT_SECONDS)

        print(f"[server] NetSentry dashboard listening on {host}:{port}")

        try:
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError as error:
                    print(f"[server] Listener socket error: {error}")
                    break

                client_thread = threading.Thread(
                    target=handle_client_connection,
                    args=(client_socket, client_address, dashboard_stats),
                    daemon=True,
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("[server] Shutdown requested by keyboard interrupt")
        finally:
            print(f"[server] Final stats: {dashboard_stats.snapshot()}")
            print("[server] Dashboard server stopped")


def build_argument_parser() -> argparse.ArgumentParser:
    """Create command-line options for the dashboard server."""
    parser = argparse.ArgumentParser(description="Run the NetSentry dashboard server.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host address to bind.")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP port for capture agent connections.",
    )
    return parser


def main() -> None:
    """Parse CLI options and start the threaded TCP dashboard server."""
    arguments = build_argument_parser().parse_args()
    start_dashboard_server(arguments.host, arguments.port)


if __name__ == "__main__":
    main()
