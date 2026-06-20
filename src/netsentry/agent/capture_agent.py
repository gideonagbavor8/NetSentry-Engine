import socket
import sys
from scapy.all import IP, TCP, UDP, Raw, sniff

# Connection settings for the local dashboard server link
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

def verify_system_configuration():
    """Validates the network configuration parameters before starting the application loop."""
    print("[Config] Checking connection endpoint parameters...")
    if not SERVER_IP.replace(".", "").isdigit():
        print("[Config Error] Target destination string is not a valid IP layout.")
        return False
    if SERVER_PORT < 1024 or SERVER_PORT > 65535:
        print("[Config Error] Port number falls outside safe custom application boundaries.")
        return False
    print("[Config] Target port configurations verified successfully.")
    return True

def format_endpoint_string(ip_address, port_number):
    """Combines an IP address and port number into a standard network endpoint format."""
    if port_number > 0:
        return f"{ip_address}:{port_number}"
    return str(ip_address)

def analyze_payload_safety(payload_text, protocol_name):
    """Scans the raw payload string layers to extract plain-text compliance security flags."""
    flags = []
    lower_payload = payload_text.lower()
    
    # Identify unencrypted credential tokens traveling through plaintext layers
    if "pass" in lower_payload or "user" in lower_payload or "password=" in lower_payload:
        flags.append("UNENCRYPTED_CREDENTIALS")
    if "http/" in lower_payload or "get " in lower_payload or "post " in lower_payload:
        flags.append("PLAINTEXT_HTTP")
        
    # Check for unsupported or unclassified transport protocols
    if protocol_name == "Other":
        flags.append("UNSUPPORTED_PROTOCOL")
        
    if not flags:
        return "SECURE"
        
    return ",".join(flags)

def process_captured_packet(packet):
    """Callback execution loop logic that intercepts, processes, and ships raw packet data rows."""
    if not packet.haslayer(IP):
        return

    # Extract source and destination network layer attributes
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = "Other"
    sport = 0
    dport = 0

    # Sort the transport layers and isolate port parameters
    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    # Convert raw payload bytes into readable characters if present
    payload_str = ""
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        payload_str = raw_data.decode("utf-8", errors="ignore").strip()

    # Run security compliance audits on the payload text
    compliance_flags = analyze_payload_safety(payload_str, proto)
    
    # Format endpoints into standard text strings
    source_str = format_endpoint_string(src_ip, sport)
    dest_str = format_endpoint_string(dst_ip, dport)
    
    # Strip delimiters from the data preview row to avoid breaking the text layout
    safe_preview = payload_str[:40].replace("|", " ").replace("\n", " ")

    # Serialize metrics row using vertical bar spacing layouts
    data_line = f"{proto}|{source_str}|{dest_str}|{compliance_flags}|{safe_preview}\n"

    # Forward the serialized line directly across a live socket stream channel
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((SERVER_IP, SERVER_PORT))
        sock.sendall(data_line.encode("utf-8"))
        sock.close()
        print(f"[Agent Sent] Forwarded parsed {proto} segment successfully.")
    except Exception as network_error:
        print(f"[Agent Error] Streaming channel dropped or timed out: {network_error}")

def main():
    print("==================================================")
    print("Starting raw packet sniffer agent pipeline...")
    print(f"Targeting server dashboard at {SERVER_IP}:{SERVER_PORT}")
    print("==================================================")
    
    # Run structural environment audits before starting up the sniffer
    if not verify_system_configuration():
        print("[Fatal System Failure] Aborting capture loop initialization.")
        sys.exit(1)
        
    try:
        # Launch Scapy sniffer tracking active local IP packets
        sniff(filter="ip", prn=process_captured_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping network packet sniffer agent application safely.")
        sys.exit(0)
    except Exception as pipeline_error:
        print(f"Pipeline tracking failure encountered: {pipeline_error}")

if __name__ == "__main__":
    main()