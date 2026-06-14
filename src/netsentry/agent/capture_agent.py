"""Scapy capture agent client for NetSentry Engine."""

from __future__ import annotations

import argparse
import queue
import socket
import threading
from typing import Any

from netsentry.common.privileges import require_admin_privileges
from netsentry.common.schemas import (
    STREAM_ENCODING,
    create_packet_metadata_template,
    sanitize_payload_preview,
    serialize_packet,
)

try:
    from scapy.all import IP, TCP, UDP, Raw, sniff
except ImportError:
    IP = TCP = UDP = Raw = sniff = None


DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 9999
CONNECT_RETRY_SECONDS = 2.0
SOCKET_TIMEOUT_SECONDS = 5.0
MAX_OUTBOUND_FRAMES = 1000
SNIFF_FILTER = "ip"

PLAINTEXT_MARKERS = (
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "HTTP/",
    "USER ",
    "PASS ",
    "password=",
    "Authorization: Basic",
)


class TelemetrySocketClient:
    """Background TCP sender with reconnect logic for dashboard telemetry."""

    def __init__(
        self,
        host: str = DEFAULT_SERVER_HOST,
        port: int = DEFAULT_SERVER_PORT,
        retry_seconds: float = CONNECT_RETRY_SECONDS,
    ) -> None:
        """Initialise the telemetry client without opening a connection.

        Args:
            host: Hostname or IP address of the NetSentry dashboard server.
            port: TCP port the dashboard server is listening on.
            retry_seconds: Seconds to wait between connection attempts when
                the dashboard is unavailable.

        The background sender thread is created here but not started until
        :meth:`start` is called.
        """
        self.host = host
        self.port = port
        self.retry_seconds = retry_seconds
        self._outbound_frames: queue.Queue[str] = queue.Queue(MAX_OUTBOUND_FRAMES)
        self._stop_event = threading.Event()
        self._socket_lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._sender_thread = threading.Thread(
            target=self._send_loop,
            name="netsentry-telemetry-sender",
            daemon=True,
        )

    def start(self) -> None:
        """Start the background thread that owns socket reconnect and sending."""
        self._sender_thread.start()

    def stop(self) -> None:
        """Stop the sender thread and close the active socket if one exists."""
        self._stop_event.set()
        self._close_socket()
        self._sender_thread.join(timeout=2.0)

    def enqueue_packet(self, packet_metadata: dict[str, Any]) -> None:
        """Serialize packet metadata and queue it for TCP transmission."""
        try:
            frame = serialize_packet(packet_metadata)
            self._outbound_frames.put_nowait(frame)
        except queue.Full:
            print("[agent] Outbound telemetry queue full. Dropping packet frame.")
        except (TypeError, ValueError) as error:
            print(f"[agent] Failed to serialize packet metadata: {error}")

    def _connect(self) -> socket.socket:
        """Connect to the dashboard server, retrying until it is available."""
        while not self._stop_event.is_set():
            try:
                client_socket = socket.create_connection(
                    (self.host, self.port),
                    timeout=SOCKET_TIMEOUT_SECONDS,
                )
                client_socket.settimeout(SOCKET_TIMEOUT_SECONDS)

                with self._socket_lock:
                    self._socket = client_socket

                print(f"[agent] Connected to dashboard at {self.host}:{self.port}")
                return client_socket
            except (ConnectionRefusedError, TimeoutError, socket.timeout):
                print(
                    f"[agent] Dashboard unavailable at {self.host}:{self.port}. "
                    f"Retrying in {self.retry_seconds} seconds."
                )
                self._stop_event.wait(self.retry_seconds)
            except (ConnectionResetError, ConnectionAbortedError) as error:
                # Server closed the connection mid-handshake (e.g. abrupt shutdown).
                print(
                    f"[agent] Dashboard dropped connection during handshake ({type(error).__name__}). "
                    f"Retrying in {self.retry_seconds} seconds."
                )
                self._stop_event.wait(self.retry_seconds)
            except OSError as error:
                print(
                    f"[agent] Dashboard connection error: {error}. "
                    f"Retrying in {self.retry_seconds} seconds."
                )
                self._stop_event.wait(self.retry_seconds)
            except Exception as error:  # noqa: BLE001
                # Guard against unexpected platform-specific or library errors so
                # the retry loop is never bypassed by an unhandled exception.
                print(
                    f"[agent] Unexpected connection error ({type(error).__name__}): {error}. "
                    f"Retrying in {self.retry_seconds} seconds."
                )
                self._stop_event.wait(self.retry_seconds)

        raise RuntimeError("Telemetry sender stopped before connecting to dashboard.")

    def _send_loop(self) -> None:
        """Continuously send queued telemetry frames over a persistent socket."""
        while not self._stop_event.is_set():
            if self._socket is None:
                try:
                    self._connect()
                except RuntimeError as error:
                    print(f"[agent] Telemetry sender stopped: {error}")
                    break
                except Exception as error:  # noqa: BLE001
                    # _connect should not raise non-RuntimeError, but guard here
                    # so an unexpected exception cannot silently kill the thread.
                    print(
                        f"[agent] Telemetry sender hit unexpected error "
                        f"({type(error).__name__}): {error}"
                    )
                    break

            try:
                frame = self._outbound_frames.get(timeout=0.5)
            except queue.Empty:
                continue

            while not self._stop_event.is_set():
                try:
                    client_socket = self._socket or self._connect()
                except RuntimeError as error:
                    print(f"[agent] Telemetry sender stopped: {error}")
                    break
                except Exception as error:  # noqa: BLE001
                    print(
                        f"[agent] Telemetry sender hit unexpected error "
                        f"({type(error).__name__}): {error}"
                    )
                    break

                try:
                    # sendall preserves the JSON Lines frame created by serialize_packet.
                    client_socket.sendall(frame.encode(STREAM_ENCODING))
                    break
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    # Server was shut down or forcibly aborted the connection.
                    print("[agent] Dashboard connection dropped. Reconnecting.")
                    self._close_socket()
                except socket.timeout:
                    print("[agent] Dashboard send timed out. Reconnecting.")
                    self._close_socket()
                except OSError as error:
                    # Catch-all for platform-specific socket errors (e.g.
                    # WSAECONNRESET on Windows which may not always surface as
                    # ConnectionResetError).
                    print(
                        f"[agent] Dashboard connection lost "
                        f"({error.errno}): {error}. Reconnecting."
                    )
                    self._close_socket()

            self._outbound_frames.task_done()

    def _close_socket(self) -> None:
        """Close the active socket while protecting shared socket state."""
        with self._socket_lock:
            client_socket = self._socket
            self._socket = None

        if client_socket is None:
            return

        try:
            client_socket.close()
        except OSError:
            pass


def extract_transport_payload(packet: Any) -> bytes:
    """Return raw packet payload bytes without executing or modifying content."""
    if Raw is not None and packet.haslayer(Raw):
        raw_load = getattr(packet[Raw], "load", b"")
        return bytes(raw_load)

    return b""


def detect_compliance_flags(payload_preview: str, protocol_type: str) -> list[str]:
    """Flag simple plaintext markers visible in sanitized packet previews."""
    compliance_flags: list[str] = []
    normalized_preview = payload_preview.lower()

    for marker in PLAINTEXT_MARKERS:
        if marker.lower() in normalized_preview:
            compliance_flags.append("PLAINTEXT_MARKER")
            break

    if protocol_type == "Other":
        compliance_flags.append("UNSUPPORTED_TRANSPORT_PROTOCOL")

    return compliance_flags


def extract_packet_metadata(packet: Any) -> dict[str, Any] | None:
    """Extract NetSentry packet metadata from a Scapy packet object.

    Returns ``None`` for non-IP packets or when Scapy is unavailable, so
    callers can skip forwarding without raising an exception.
    """
    if IP is None or TCP is None or UDP is None:
        # Scapy unavailability is detected once at import time (IP et al. are
        # set to None by the try/except block at the top of this module).  We
        # do not log here because this function is called once per captured
        # packet; the startup check in start_capture_agent handles the message.
        return None

    if not packet.haslayer(IP):
        return None

    packet_metadata = create_packet_metadata_template()
    ip_layer = packet[IP]
    packet_metadata["source_ip"] = getattr(ip_layer, "src", "")
    packet_metadata["destination_ip"] = getattr(ip_layer, "dst", "")

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        packet_metadata["protocol_type"] = "TCP"
        packet_metadata["source_port"] = getattr(tcp_layer, "sport", None)
        packet_metadata["destination_port"] = getattr(tcp_layer, "dport", None)
        packet_metadata["tcp_flags"] = str(getattr(tcp_layer, "flags", ""))
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        packet_metadata["protocol_type"] = "UDP"
        packet_metadata["source_port"] = getattr(udp_layer, "sport", None)
        packet_metadata["destination_port"] = getattr(udp_layer, "dport", None)
    else:
        packet_metadata["protocol_type"] = "Other"

    packet_metadata["payload_preview"] = extract_transport_payload(packet)
    sanitized_preview = sanitize_payload_preview(packet_metadata["payload_preview"])
    packet_metadata["compliance_flags"] = detect_compliance_flags(
        sanitized_preview,
        str(packet_metadata["protocol_type"]),
    )

    return packet_metadata


from collections.abc import Callable


def build_packet_processor(
    telemetry_client: TelemetrySocketClient,
) -> Callable[[Any], None]:
    """Return a Scapy-compatible callback that streams packet metadata to the dashboard.

    The returned closure captures *telemetry_client* and is passed directly to
    :func:`scapy.all.sniff` as the ``prn`` argument.  Any exception raised
    during metadata extraction or queuing is caught and logged so that Scapy's
    capture loop is never interrupted by a processing error.
    """

    def process_packet(packet: Any) -> None:
        """Extract metadata from one Scapy packet and enqueue it for transmission."""
        try:
            packet_metadata = extract_packet_metadata(packet)
            if packet_metadata is None:
                return

            telemetry_client.enqueue_packet(packet_metadata)
        except Exception as error:
            print(f"[agent] Packet processing error: {error}")

    return process_packet


def start_capture_agent(
    host: str = DEFAULT_SERVER_HOST,
    port: int = DEFAULT_SERVER_PORT,
    interface: str | None = None,
) -> None:
    """Validate privileges, connect telemetry, and start Scapy sniffing."""
    try:
        require_admin_privileges()
    except PermissionError as error:
        print(f"[agent] {error}")
        return

    if sniff is None:
        print("[agent] Scapy is not installed. Run: python -m pip install -r requirements.txt")
        return

    telemetry_client = TelemetrySocketClient(host=host, port=port)
    telemetry_client.start()

    print(
        f"[agent] Starting packet capture with filter={SNIFF_FILTER} "
        f"interface={interface or 'default'}"
    )

    try:
        sniff(
            filter=SNIFF_FILTER,
            iface=interface,
            prn=build_packet_processor(telemetry_client),
            store=0,
        )
    except PermissionError as error:
        print(f"[agent] Packet capture permission error: {error}")
    except OSError as error:
        print(f"[agent] Packet capture driver or interface error: {error}")
    except KeyboardInterrupt:
        print("[agent] Capture stopped by keyboard interrupt")
    except Exception as error:
        print(f"[agent] Unexpected packet capture error: {error}")
    finally:
        telemetry_client.stop()
        print("[agent] Capture agent stopped")


def build_argument_parser() -> argparse.ArgumentParser:
    """Create command-line options for the capture agent."""
    parser = argparse.ArgumentParser(description="Run the NetSentry capture agent.")
    parser.add_argument("--host", default=DEFAULT_SERVER_HOST, help="Dashboard host.")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_SERVER_PORT,
        help="Dashboard TCP port.",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Optional network interface name for Scapy sniffing.",
    )
    return parser


def main() -> None:
    """Parse CLI options and start the capture agent."""
    arguments = build_argument_parser().parse_args()
    start_capture_agent(arguments.host, arguments.port, arguments.interface)


if __name__ == "__main__":
    main()
