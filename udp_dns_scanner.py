import socket
import sys

def udp_dns_scanner(target, port=53):
    """
    UDP scanning uses socket.SOCK_DGRAM because UDP is connectionless.
    We send a UDP datagram to the DNS port and wait for a response.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # UDP often has no response when filtered, so we use a timeout to avoid hanging.
    udp_sock.settimeout(2.0)

    # This is a basic DNS query asking for an A record for example.com.
    # The bytes represent a valid DNS request packet format.
    query = (
        b"\x12\x34"  # Transaction ID
        b"\x01\x00"  # Standard query
        b"\x00\x01"  # Questions: 1
        b"\x00\x00"  # Answer RRs: 0
        b"\x00\x00"  # Authority RRs: 0
        b"\x00\x00"  # Additional RRs: 0
        b"\x07example\x03com\x00"  # QNAME: example.com
        b"\x00\x01"  # QTYPE: A
        b"\x00\x01"  # QCLASS: IN
    )

    try:
        udp_sock.sendto(query, (target, port))

        # recvfrom(512) is used because classic DNS over UDP responses are typically <= 512 bytes
        # (EDNS can exceed this, but 512 is a standard safe default for lab DNS checks).
        response, _ = udp_sock.recvfrom(512)

        if response:
            print(f"[*] Port {port}/udp (DNS) is open and responding")
            return True

    except socket.timeout:
        # UDP scanning often times out because UDP has no handshake.
        # No response can mean the port is open|filtered or filtered by a firewall.
        print(f"[-] Port {port}/udp (DNS) did not respond (open|filtered or filtered)")
        return False

    finally:
        # Always close sockets so file descriptors/resources are not leaked.
        udp_sock.close()

def main():
    """
    sys.argv allows us to accept the target IP as a command-line argument.
    Input validation matters so the script runs predictably and avoids scanning the wrong host.
    """
    if len(sys.argv) != 2:
        print("Usage: python3 udp_dns_scanner.py <Metasploitable-2_IP>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Scanning UDP DNS port 53 on {target}...")
    udp_dns_scanner(target)

if __name__ == "__main__":
    main()