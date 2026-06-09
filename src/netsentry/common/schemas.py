"""Shared packet telemetry schema and stream serialization helpers."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any


MAX_PAYLOAD_PREVIEW_LENGTH = 160
JSON_FRAME_DELIMITER = "\n"

PACKET_METADATA_TEMPLATE: dict[str, Any] = {
    "timestamp": "",
    "protocol_type": "Other",
    "source_ip": "",
    "destination_ip": "",
    "source_port": None,
    "destination_port": None,
    "tcp_flags": "",
    "payload_preview": "",
    "compliance_flags": [],
}


def create_packet_metadata_template() -> dict[str, Any]:
    """Return a fresh packet metadata dictionary with the expected keys."""
    template = copy.deepcopy(PACKET_METADATA_TEMPLATE)
    template["timestamp"] = datetime.now(timezone.utc).isoformat()
    return template


def sanitize_payload_preview(
    raw_payload: bytes | bytearray | memoryview | str | None,
    max_length: int = MAX_PAYLOAD_PREVIEW_LENGTH,
) -> str:
    """Convert raw packet payload data into a bounded, JSON-safe text preview."""
    if raw_payload is None:
        return ""

    if isinstance(raw_payload, str):
        payload_text = raw_payload
    else:
        payload_bytes = bytes(raw_payload)
        payload_text = payload_bytes.decode("utf-8", errors="replace")

    safe_characters: list[str] = []
    for character in payload_text:
        if character == "\ufffd":
            safe_characters.append("[UNREADABLE]")
        elif character.isprintable() or character in ("\t", "\r", "\n"):
            safe_characters.append(character)
        else:
            safe_characters.append("[UNREADABLE]")

    sanitized_payload = "".join(safe_characters)
    sanitized_payload = sanitized_payload.replace("\r", "\\r").replace("\n", "\\n")

    if len(sanitized_payload) <= max_length:
        return sanitized_payload

    return sanitized_payload[:max_length] + "[TRUNCATED]"


def normalize_packet_metadata(packet_dict: dict[str, Any]) -> dict[str, Any]:
    """Copy user packet data into the expected schema and sanitize the payload."""
    normalized_packet = create_packet_metadata_template()

    for field_name in normalized_packet:
        if field_name in packet_dict:
            normalized_packet[field_name] = packet_dict[field_name]

    normalized_packet["protocol_type"] = str(
        normalized_packet.get("protocol_type") or "Other"
    )
    normalized_packet["payload_preview"] = sanitize_payload_preview(
        normalized_packet.get("payload_preview")
    )

    compliance_flags = normalized_packet.get("compliance_flags")
    if compliance_flags is None:
        normalized_packet["compliance_flags"] = []
    elif not isinstance(compliance_flags, list):
        normalized_packet["compliance_flags"] = [str(compliance_flags)]
    else:
        normalized_packet["compliance_flags"] = [str(flag) for flag in compliance_flags]

    return normalized_packet


def serialize_packet(packet_dict: dict[str, Any]) -> str:
    """Encode packet metadata as one newline-delimited JSON frame."""
    normalized_packet = normalize_packet_metadata(packet_dict)

    # The newline delimiter marks one complete message over the raw TCP stream.
    return (
        json.dumps(normalized_packet, ensure_ascii=True, separators=(",", ":"))
        + JSON_FRAME_DELIMITER
    )
