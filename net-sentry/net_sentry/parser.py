import struct
import socket

def format_mac(raw_bytes):
    """Formats 6 raw bytes into standard hex MAC address (e.g., aa:bb:cc:dd:ee:ff)."""
    return ":".join(f"{b:02x}" for b in raw_bytes)

class PacketParser:
    """Zero-dependency low-level binary packet dissection engine (RFC 791, 793, 768, 826)."""

    @staticmethod
    def parse_ethernet(data):
        """Unpacks 14-byte Ethernet II frame header."""
        if len(data) < 14:
            return None
        dest_mac, src_mac, eth_type = struct.unpack("!6s6sH", data[:14])
        return {
            "dest_mac": format_mac(dest_mac),
            "src_mac": format_mac(src_mac),
            "eth_type": eth_type,
            "payload": data[14:]
        }

    @staticmethod
    def parse_arp(data):
        """Unpacks 28-byte Address Resolution Protocol (ARP) packet (RFC 826)."""
        if len(data) < 28:
            return None
        hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, tgt_mac, tgt_ip = struct.unpack(
            "!HHBBH6s4s6s4s", data[:28]
        )
        return {
            "hw_type": hw_type,
            "proto_type": proto_type,
            "opcode": opcode,  # 1 = Request, 2 = Reply
            "src_mac": format_mac(src_mac),
            "src_ip": socket.inet_ntoa(src_ip),
            "dest_mac": format_mac(tgt_mac),
            "dest_ip": socket.inet_ntoa(tgt_ip),
            "is_reply": opcode == 2,
            "is_request": opcode == 1
        }

    @staticmethod
    def parse_ipv4(data):
        """Unpacks IPv4 header (minimum 20 bytes) (RFC 791)."""
        if len(data) < 20:
            return None
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        if len(data) < ihl:
            return None

        tos, total_len, identification, flags_frag, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack(
            "!BHHHBBH4s4s", data[1:20]
        )
        return {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_len": total_len,
            "ttl": ttl,
            "protocol": protocol,  # 1 = ICMP, 6 = TCP, 17 = UDP
            "src_ip": socket.inet_ntoa(src_ip),
            "dest_ip": socket.inet_ntoa(dest_ip),
            "payload": data[ihl:]
        }

    @staticmethod
    def parse_tcp(data):
        """Unpacks TCP segment header (minimum 20 bytes) (RFC 793)."""
        if len(data) < 20:
            return None
        src_port, dest_port, seq, ack, offset_reserved, flags, window, checksum, urgent = struct.unpack(
            "!HHIIBBHHH", data[:20]
        )
        offset = (offset_reserved >> 4) * 4
        if len(data) < offset:
            return None

        # Decode TCP Flags
        flag_dict = {
            "URG": bool(flags & 0x20),
            "ACK": bool(flags & 0x10),
            "PSH": bool(flags & 0x08),
            "RST": bool(flags & 0x04),
            "SYN": bool(flags & 0x02),
            "FIN": bool(flags & 0x01)
        }

        # Check special stealth scan flag combinations
        is_null_scan = flags == 0
        is_fin_scan = flags == 0x01
        is_xmas_scan = bool(flags & 0x20 and flags & 0x08 and flags & 0x01)  # URG + PSH + FIN
        is_syn_only = bool(flags == 0x02)

        return {
            "src_port": src_port,
            "dest_port": dest_port,
            "seq": seq,
            "ack": ack,
            "offset": offset,
            "flags": flag_dict,
            "raw_flags": flags,
            "is_null_scan": is_null_scan,
            "is_fin_scan": is_fin_scan,
            "is_xmas_scan": is_xmas_scan,
            "is_syn_only": is_syn_only,
            "payload": data[offset:]
        }

    @staticmethod
    def parse_udp(data):
        """Unpacks UDP header (8 bytes) (RFC 768)."""
        if len(data) < 8:
            return None
        src_port, dest_port, length, checksum = struct.unpack("!HHHH", data[:8])
        return {
            "src_port": src_port,
            "dest_port": dest_port,
            "length": length,
            "payload": data[8:length] if length <= len(data) else data[8:]
        }

    @staticmethod
    def parse_dns_query(data):
        """Extracts queried domain name from DNS header (RFC 1035)."""
        if len(data) < 12:
            return None
        # DNS Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        try:
            qdcount = struct.unpack("!H", data[4:6])[0]
            if qdcount < 1:
                return None

            # Parse QNAME: sequences of <length_byte><label_bytes> ending in 0x00
            idx = 12
            labels = []
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    break
                # Handle pointer compression (0xC0)
                if (length & 0xC0) == 0xC0:
                    idx += 2
                    break
                idx += 1
                if idx + length > len(data):
                    break
                labels.append(data[idx:idx + length].decode("ascii", errors="ignore"))
                idx += length

            if labels:
                return ".".join(labels)
        except Exception:
            pass
        return None

    @staticmethod
    def parse_http(data):
        """Parses basic HTTP request methods, headers, and form credentials."""
        try:
            text = data.decode("utf-8", errors="ignore")
            lines = text.split("\r\n")
            if not lines:
                return None

            first_line = lines[0].strip()
            methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")
            if not any(first_line.startswith(m) for m in methods):
                return None

            parts = first_line.split()
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            uri = parts[1] if len(parts) > 1 else "/"

            headers = {}
            body = ""
            is_body = False
            for line in lines[1:]:
                if is_body:
                    body += line + "\n"
                elif line == "":
                    is_body = True
                else:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

            return {
                "method": method,
                "uri": uri,
                "headers": headers,
                "body": body.strip()
            }
        except Exception:
            return None
