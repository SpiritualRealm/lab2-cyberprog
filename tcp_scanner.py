import socket
import sys

def tcp_scanner(target, port):
    """
    socket.AF_INET selects the IPv4 address family.
    socket.SOCK_STREAM selects TCP (a reliable, connection-oriented protocol).
    Together, they create an IPv4 TCP socket suitable for connecting to TCP ports.
    """
    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # settimeout(1) prevents the scanner from hanging on filtered ports
        # by limiting how long connect() can wait before failing.
        tcp_sock.settimeout(1)

        tcp_sock.connect((target, port))
        tcp_sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        """
        Common exceptions include:
        - socket.timeout: no response within timeout (filtered or dropped packets)
        - ConnectionRefusedError: target replied with RST (port closed)
        - OSError: network errors (no route, invalid host, etc.)
        """
        return False

def main():
    """
    We check len(sys.argv) to ensure the user provides the target IP address.
    Without proper input, the script cannot know which host to scan.
    """
    if len(sys.argv) != 2:
        print("Usage: python3 tcp_scanner.py <Metasploitable-2_IP>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Scanning TCP ports 1-1024 on {target}...")

    """
    We loop through ports 1-1024 because these are the well-known ports.
    They commonly host standard services (FTP, SSH, HTTP, etc.) and are a typical first scan range.
    """
    for port in range(1, 1025):
        if tcp_scanner(target, port):
            print(f"[*] Port {port}/tcp is open")

if __name__ == "__main__":
    main()