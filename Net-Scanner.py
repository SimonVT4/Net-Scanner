import socket
import threading
import os
import time

# Global lists to store the results
open_ports = []
closed_ports = []
error_ports = []


# Function for TCP Port Scanning
def tcp_scan(host, port):
    """Check if a given TCP port is open on the specified host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
    except Exception as e:
        error_ports.append((port, str(e)))


# Function for UDP Port Scanning
def udp_scan(host, port):
    """Check if a given UDP port is open on the specified host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"Test", (host, port))
        try:
            sock.recvfrom(1024)
            open_ports.append(port)
        except socket.timeout:
            closed_ports.append(port)  # No response might mean closed
    except Exception as e:
        error_ports.append((port, str(e)))


# Function for ICMP (Ping) Scan
def icmp_scan(host, count, timeout):
    """Perform an ICMP ping to check if the host is reachable with user-defined options."""
    try:
        print(f"\n--- Performing ICMP Ping to {host} ---")
        print(f"Sending {count} ping request(s) with a timeout of {timeout} second(s) each...\n")

        # Construct the ping command based on the operating system
        if os.name == "nt":
            # Windows uses -n for the number of pings and -w for the timeout (in milliseconds)
            ping_command = f"ping -n {count} -w {timeout * 1000} {host}"
        else:
            # Unix-like systems use -c for the number of pings and -W for the timeout (in seconds)
            ping_command = f"ping -c {count} -W {timeout} {host}"

        response = os.system(ping_command)
        if response == 0:
            print(f"\nICMP Ping to {host} successful. The host is reachable.")
        else:
            print(f"\nICMP Ping to {host} failed. The host might be unreachable or blocking ICMP requests.")

        print("\n--- End of ICMP Scan ---")
    except Exception as e:
        print(f"Error during ICMP scan: {e}")


# Function to Handle the Scanning Logic
def scan_ports(host, protocol, start_port, end_port):
    """Scan a range of ports using the specified protocol."""
    if protocol in ["TCP", "UDP"]:
        print(f"\nScanning {host} from port {start_port} to {end_port} using {protocol}...\n")

    start_time = time.time()

    if protocol == "TCP":
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=tcp_scan, args=(host, port))
            thread.start()
        thread.join()

    elif protocol == "UDP":
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=udp_scan, args=(host, port))
            thread.start()
        thread.join()

    elif protocol == "ICMP":
        # Prompt the user for the number of pings and the timeout duration
        while True:
            try:
                count = int(input("Enter the number of ping requests to send: "))
                if count < 1:
                    print("Number of ping requests must be at least 1. Please try again.")
                    continue
                timeout = int(input("Enter the timeout for each ping request (in seconds): "))
                if timeout < 1:
                    print("Timeout must be at least 1 second. Please try again.")
                    continue
                break
            except ValueError:
                print("Invalid input. Please enter a valid integer.")

        icmp_scan(host, count, timeout)
        return  # End after ICMP scan

    end_time = time.time()
    duration = end_time - start_time

    # Summarize the results (for TCP and UDP scans only)
    print("\n--- Scan Summary ---")
    print(f"Total Ports Scanned: {end_port - start_port + 1}")
    print(f"Total Open Ports: {len(open_ports)}")
    print(f"Total Closed Ports: {len(closed_ports)}")
    print(f"Total Errors: {len(error_ports)}")
    print(f"Total Scan Duration: {duration:.2f} seconds\n")

    if open_ports:
        print(f"Open Ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found.")

    if closed_ports:
        print(f"\nClosed Ports: {', '.join(map(str, closed_ports))}")
    else:
        print("No closed ports found.")

    if error_ports:
        print("\nErrors encountered during scanning:")
        for port, error in error_ports:
            print(f"Port {port}: {error}")
    else:
        print("\nNo errors encountered during scanning.")


# Main Function
if __name__ == "__main__":
    # Warning Message
    print("\n--- WARNING ---")
    print(
        "Unauthorized port scanning can be illegal and unethical. Only scan IP addresses that you own or have explicit permission to test.")
    print("Use this tool responsibly and in compliance with all applicable laws.\n")

    # Example Input
    print("Example Input: 'localhost' or '192.168.1.1' for a local network scan, '8.8.8.8' for an external scan.\n")

    while True:
        host = input("Enter the target host (for example: 'localhost' or '192.168.1.1'): ").strip()
        if host:
            break
        print("Host cannot be empty. Please enter a valid target host.")

    while True:
        protocol = input("Enter the protocol (TCP, UDP, ICMP): ").strip().upper()
        if protocol in ["TCP", "UDP", "ICMP"]:
            break
        print("Invalid protocol. Please choose TCP, UDP, or ICMP.")

    if protocol in ["TCP", "UDP"]:
        while True:
            try:
                start_port = int(input("Enter the starting port (1-65535): "))
                end_port = int(input("Enter the ending port (1-65535): "))
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    break
                print("Invalid port range! Please enter a valid range (1-65535).")
            except ValueError:
                print("Invalid input. Please enter valid integers for the port range.")

        scan_ports(host, protocol, start_port, end_port)
    elif protocol == "ICMP":
        scan_ports(host, protocol, 0, 0)
