"""Shared packet telemetry schema and stream serialization helpers."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any


MAX_PAYLOAD_PREVIEW_LENGTH = 160

# Single canonical encoding used by both the capture agent and the dashboard
# server.  Both sides must agree on this value; changing it here is the only
# place that needs touching.
STREAM_ENCODING = "utf-8"

# Newline-delimited JSON (NDJSON) framing: every serialized packet is exactly
# one JSON object followed by a single 0x0A byte.  The server splits on this
# byte to reassemble frames across TCP segment boundaries.
JSON_FRAME_DELIMITER = "\n"

# Canonical packet schema.  ``create_packet_metadata_template`` deep-copies
# this dict so callers always receive an independent, mutable instance.
# Do not mutate this module-level constant directly.
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
        payload_text = payload_bytes.decode(STREAM_ENCODING, errors="replace")

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
    """Copy caller-supplied packet data into the canonical schema and normalize fields.

    Three normalization steps are applied in order:

    1. **Schema merge** – only keys present in ``PACKET_METADATA_TEMPLATE`` are
       copied, so unknown fields from callers are silently ignored.
    2. **Protocol coercion** – ``protocol_type`` is cast to ``str`` and
       defaults to ``"Other"`` if falsy.
    3. **Payload sanitization** – raw bytes are decoded, non-printable
       characters replaced, newlines escaped, and the preview truncated to
       ``MAX_PAYLOAD_PREVIEW_LENGTH`` characters.
    4. **Compliance flag coercion** – the ``compliance_flags`` value is
       normalised to a ``list[str]`` regardless of what the caller passed.
    """
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
    """Encode packet metadata as one newline-delimited JSON frame.

    The returned string is always exactly one JSON object followed by a single
    newline (0x0A).  The server's ``split_stream_buffer`` relies on this
    guarantee to split concurrent frames arriving in a single TCP segment.

    Why a literal newline cannot appear inside the JSON body:
    - ``ensure_ascii=True`` prevents any multi-byte UTF-8 sequence from
      containing 0x0A as a continuation byte.
    - ``json.dumps`` encodes every control character in string values as a
      JSON escape (e.g. ``\\n``), so no raw 0x0A survives inside a string.
    - ``sanitize_payload_preview`` additionally pre-escapes ``\\n`` in the
      payload before ``json.dumps`` is called, providing defence-in-depth.
    - Non-string values (int, None, bool, list) never contain newlines.
    """
    normalized_packet = normalize_packet_metadata(packet_dict)

    json_body = json.dumps(normalized_packet, ensure_ascii=True, separators=(",", ":"))

    # Sanity-check the invariant: the body must be newline-free so that the
    # single appended delimiter is unambiguous.  This assertion can never fire
    # given the properties above, but it surfaces any future regression
    # (e.g. a new field that bypasses sanitization) immediately at write time.
    assert JSON_FRAME_DELIMITER not in json_body, (
        "serialize_packet: JSON body contains a literal newline before the "
        "frame delimiter was appended.  This would corrupt the NDJSON stream."
    )

    return json_body + JSON_FRAME_DELIMITER
