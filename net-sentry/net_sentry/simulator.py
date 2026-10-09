import socket
import struct
import time

def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))

def build_ethernet_frame(dest_mac, src_mac, eth_type, payload):
    dest_b = mac_to_bytes(dest_mac)
    src_b = mac_to_bytes(src_mac)
    return struct.pack("!6s6sH", dest_b, src_b, eth_type) + payload

def build_ipv4_packet(src_ip, dest_ip, protocol, payload):
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    ident = 0xbeef
    flags_frag = 0
    ttl = 64
    checksum = 0
    src_b = socket.inet_aton(src_ip)
    dest_b = socket.inet_aton(dest_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_b,
        dest_b
    )
    return header + payload

def build_tcp_segment(src_port, dest_port, flags, seq=1000, ack=0, payload=b""):
    offset_res = (5 << 4)
    window = 8192
    checksum = 0
    urgent = 0
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dest_port,
        seq,
        ack,
        offset_res,
        flags,
        window,
        checksum,
        urgent
    )
    return header + payload

def build_udp_datagram(src_port, dest_port, payload=b""):
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dest_port, length, checksum)
    return header + payload

def build_arp_packet(opcode, sender_mac, sender_ip, target_mac, target_ip):
    hw_type = 1  # Ethernet
    proto_type = 0x0800  # IPv4
    hw_size = 6
    proto_size = 4
    s_mac_b = mac_to_bytes(sender_mac)
    s_ip_b = socket.inet_aton(sender_ip)
    t_mac_b = mac_to_bytes(target_mac)
    t_ip_b = socket.inet_aton(target_ip)
    return struct.pack(
        "!HHBBH6s4s6s4s",
        hw_type,
        proto_type,
        hw_size,
        proto_size,
        opcode,
        s_mac_b,
        s_ip_b,
        t_mac_b,
        t_ip_b
    )

def build_dns_query(domain_name, tx_id=0x1234):
    flags = 0x0100  # Standard query with recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    qname = b""
    for part in domain_name.split("."):
        qname += struct.pack("!B", len(part)) + part.encode("ascii")
    qname += b"\x00"

    qtype_qclass = struct.pack("!HH", 1, 1)  # Type A, Class IN
    return header + qname + qtype_qclass

class TrafficSimulator:
    """Synthesizes realistic malicious and benign raw packet streams for testing."""

    @classmethod
    def generate_attack_stream(cls):
        """Generates a complete sequence of benign + simulated attack packets."""
        packets = []

        # 1. Benign Normal HTTP Traffic
        http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        tcp_payload = build_tcp_segment(49152, 80, flags=0x18, payload=http_req)  # ACK + PSH
        ip_payload = build_ipv4_packet("192.168.1.50", "93.184.216.34", protocol=6, payload=tcp_payload)
        packets.append({
            "name": "Benign HTTP Request",
            "bytes": build_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:01", 0x0800, ip_payload)
        })

        # 2. Attack: Stealth XMAS Scan (nmap -sX)
        xmas_tcp = build_tcp_segment(54321, 445, flags=0x29)  # URG + PSH + FIN
        xmas_ip = build_ipv4_packet("10.0.0.99", "192.168.1.10", protocol=6, payload=xmas_tcp)
        packets.append({
            "name": "Stealth XMAS Port Scan Probe",
            "bytes": build_ethernet_frame("00:11:22:33:44:55", "de:ad:be:ef:00:99", 0x0800, xmas_ip)
        })

        # 3. Attack: Multi-Port Recon Sweep (Port Scan)
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 8080]
        for p in scan_ports:
            syn_tcp = build_tcp_segment(40000 + p, p, flags=0x02)  # SYN only
            syn_ip = build_ipv4_packet("10.0.0.99", "192.168.1.10", protocol=6, payload=syn_tcp)
            packets.append({
                "name": f"Port Scan Probe to Port {p}",
                "bytes": build_ethernet_frame("00:11:22:33:44:55", "de:ad:be:ef:00:99", 0x0800, syn_ip)
            })

        # 4. Attack: ARP Poisoning / Spoofing (Gateway MAC Conflict)
        # Legitimate gateway ARP announcement
        arp_legit = build_arp_packet(2, "00:aa:bb:cc:dd:ee", "192.168.1.1", "ff:ff:ff:ff:ff:ff", "192.168.1.10")
        packets.append({
            "name": "Legitimate Gateway ARP Announcement",
            "bytes": build_ethernet_frame("ff:ff:ff:ff:ff:ff", "00:aa:bb:cc:dd:ee", 0x0806, arp_legit)
        })
        # Malicious attacker claiming Gateway IP
        arp_spoof = build_arp_packet(2, "de:ad:be:ef:66:66", "192.168.1.1", "ff:ff:ff:ff:ff:ff", "192.168.1.10")
        packets.append({
            "name": "Malicious ARP Spoofing Packet",
            "bytes": build_ethernet_frame("ff:ff:ff:ff:ff:ff", "de:ad:be:ef:66:66", 0x0806, arp_spoof)
        })

        # 5. Attack: SYN Flood Denial of Service
        for i in range(45):
            flood_tcp = build_tcp_segment(10000 + i, 80, flags=0x02)
            flood_ip = build_ipv4_packet("203.0.113.88", "192.168.1.10", protocol=6, payload=flood_tcp)
            packets.append({
                "name": "SYN Flood DoS Packet",
                "bytes": build_ethernet_frame("00:11:22:33:44:55", "de:ad:be:ef:11:11", 0x0800, flood_ip)
            })

        # 6. Attack: DNS Tunneling Data Exfiltration (High Entropy Base64 Subdomain)
        suspicious_qname = "NTRhNzM2OTY3NmU2MTZmMjA2NTc4NjY2OTZjLnBhc3N3b3Jkcy5leGZpbA.c2-command.darknet.ru"
        dns_payload = build_dns_query(suspicious_qname)
        udp_dns = build_udp_datagram(53535, 53, dns_payload)
        ip_dns = build_ipv4_packet("192.168.1.45", "8.8.8.8", protocol=17, payload=udp_dns)
        packets.append({
            "name": "DNS Tunneling Exfiltration Packet",
            "bytes": build_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:01", 0x0800, ip_dns)
        })

        # 7. Attack: Cleartext Credential Transmission over HTTP
        login_body = "username=admin_corp&password=ProductionSecretPassword2026!&submit=Login"
        login_req = f"POST /api/v1/auth HTTP/1.1\r\nHost: insecure-intranet.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(login_body)}\r\n\r\n{login_body}".encode()
        login_tcp = build_tcp_segment(52100, 80, flags=0x18, payload=login_req)
        login_ip = build_ipv4_packet("192.168.1.45", "10.10.10.50", protocol=6, payload=login_tcp)
        packets.append({
            "name": "Cleartext HTTP Credential Leak",
            "bytes": build_ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:01", 0x0800, login_ip)
        })

        return packets
