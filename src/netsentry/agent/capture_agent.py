"""Bootstrap entry point for the NetSentry capture agent client."""

from __future__ import annotations

from netsentry.common.privileges import require_admin_privileges


def main() -> None:
    """Validate runtime permissions before the future Scapy sniffer starts."""
    require_admin_privileges()
    print("NetSentry capture agent bootstrap ready.")


if __name__ == "__main__":
    main()
