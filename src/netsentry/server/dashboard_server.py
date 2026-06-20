import socket
import sys
import os

BIND_IP = "127.0.0.1"
BIND_PORT = 9999
LOG_FILE_PATH = "packet_history_log.txt"

def initialize_storage_environment():
    """Verifies and prepares the text storage file layout environment on the local disk."""
    print("[Storage] Initializing tracking log files...")
    try:
        if not os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write("=== NETSENTRY PACKET TELEMETRY HISTORY SYSTEM LOG ===\n")
            print(f"[Storage] Created new telemetry text database file: {LOG_FILE_PATH}")
        else:
            print(f"[Storage] Appending telemetry to active text database file: {LOG_FILE_PATH}")
        return True
    except Exception as storage_error:
        print(f"[Storage Error] Failed to configure tracking environment: {storage_error}")
        return False

def print_log_record(count, proto, src, dest, compliance, preview):
    """Outputs structured network telemetry records down onto the monitoring screen console."""
    print(f"--- [Network Trace Log Record #{count}] ---")
    print(f"  Protocol Identity:  {proto}")
    print(f"  Source Endpoint:    {src}")
    print(f"  Target Destination: {dest}")
    print(f"  Compliance Rating:  {compliance}")
    print(f"  Payload Material:   {preview}")
    print("-" * 45)

def append_to_backup_file(count, proto, src, dest, compliance, preview):
    """Saves telemetry updates permanently into a localized text storage script backup log."""
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"Record #{count} | {proto} | From: {src} | To: {dest} | Status: {compliance} | Data: {preview}\n")
    except Exception as file_error:
        print(f"[Storage Warning] File system block writing failure: {file_error}")

def run_dashboard():
    """Initializes and runs the streaming network dashboard backend socket listener interface."""
    # Build out and clear workspace data logs
    if not initialize_storage_environment():
        print("[Fatal Error] Aborting server listener initialization due to storage blocks.")
        sys.exit(1)

    # Establish raw TCP streaming interface channels
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
        server.listen(5)
        print("==================================================")
        print(f"Dashboard Monitor Server live at {BIND_IP}:{BIND_PORT}")
        print("==================================================")
    except Exception as socket_error:
        print(f"Failed to bind socket streaming listener port boundaries: {socket_error}")
        sys.exit(1)

    packet_counter = 0

    try:
        while True:
            # Standby for incoming stream data packets pushed out by client agents
            client_sock, client_addr = server.accept()
            raw_bytes = client_sock.recv(4096)
            
            if not raw_bytes:
                client_sock.close()
                continue

            message_line = raw_bytes.decode("utf-8", errors="ignore").strip()
            client_sock.close()

            if not message_line:
                continue

            packet_counter += 1

            # Break apart the custom vertical bar text layout blocks
            try:
                segments = message_line.split("|")
                protocol = segments[0]
                source = segments[1]
                destination = segments[2]
                compliance = segments[3]
                preview = segments[4] if len(segments) > 4 else "None"

                # Push structural logs down into terminal screen updates
                print_log_record(packet_counter, protocol, source, destination, compliance, preview)
                
                # Append data record metrics permanently onto disk logs
                append_to_backup_file(packet_counter, protocol, source, destination, compliance, preview)
                
            except Exception as parse_error:
                print(f"[Server Warning] Received unexpected string configuration: {message_line} | {parse_error}")

    except KeyboardInterrupt:
        print("\nDashboard monitoring server engine closing down smoothly.")
    finally:
        server.close()
        print("Server socket interfaces disconnected successfully.")

if __name__ == "__main__":
    run_dashboard()