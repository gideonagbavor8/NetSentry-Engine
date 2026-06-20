import socket
import sys

BIND_IP = "127.0.0.1"
BIND_PORT = 9999
LOG_FILE_PATH = "packet_history_log.txt"

def print_log_record(count, proto, src, dest, compliance, preview):
    """Outputs structured metric telemetry logs down into the console screen."""
    print(f"--- [Network Trace Log Record #{count}] ---")
    print(f"  Protocol Identity:  {proto}")
    print(f"  Source Endpoint:    {src}")
    print(f"  Target Destination: {dest}")
    print(f"  Compliance Rating:  {compliance}")
    print(f"  Payload Material:   {preview}")
    print("-" * 45)

def append_to_backup_file(count, proto, src, dest, compliance, preview):
    """Saves telemetry lines permanently onto a local text backup log file."""
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"Record #{count} | {proto} | From: {src} | To: {dest} | Status: {compliance} | Data: {preview}\n")
    except Exception as e:
        print(f"[Storage Warning] File backup failure encountered: {e}")

def run_dashboard():
    # Setup simple TCP streaming socket listener
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
        server.listen(5)
        print("==================================================")
        print(f"Dashboard Monitor Server live at {BIND_IP}:{BIND_PORT}")
        print(f"Local text data log saving into: {LOG_FILE_PATH}")
        print("==================================================")
    except Exception as e:
        print(f"Failed to open socket interface tracking channels: {e}")
        sys.exit(1)

    packet_counter = 0

    try:
        while True:
            # Handle incoming telemetry connections from the capture client agent
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

            # Process custom vertical bar serialization blocks
            try:
                segments = message_line.split("|")
                protocol = segments[0]
                source = segments[1]
                destination = segments[2]
                compliance = segments[3]
                preview = segments[4] if len(segments) > 4 else "None"

                # Update terminal console displays
                print_log_record(packet_counter, protocol, source, destination, compliance, preview)
                
                # Append rows into local storage files
                append_to_backup_file(packet_counter, protocol, source, destination, compliance, preview)
                
            except Exception:
                print(f"[Server Warning] Received non-standard layout string format: {message_line}")

    except KeyboardInterrupt:
        print("\nDashboard monitoring server stopping gracefully.")
    finally:
        server.close()
        print("Server socket shut down cleanly.")

if __name__ == "__main__":
    run_dashboard()