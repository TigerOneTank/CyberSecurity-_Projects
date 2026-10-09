import struct
import socket

def hex_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)

class PacketParser:
    @staticmethod
    def parse_ethernet(buf):
        if len(buf) < 14:
            return None
        dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", buf[:14])
        return {
            "dest_mac": hex_mac(dst_mac),
            "src_mac": hex_mac(src_mac),
            "eth_type": eth_type,
            "payload": buf[14:]
        }

    @staticmethod
    def parse_arp(buf):
        if len(buf) < 28:
            return None
        hw_t, proto_t, hw_sz, proto_sz, op, s_mac, s_ip, t_mac, t_ip = struct.unpack(
            "!HHBBH6s4s6s4s", buf[:28]
        )
        return {
            "hw_type": hw_t,
            "proto_type": proto_t,
            "opcode": op,
            "src_mac": hex_mac(s_mac),
            "src_ip": socket.inet_ntoa(s_ip),
            "dest_mac": hex_mac(t_mac),
            "dest_ip": socket.inet_ntoa(t_ip),
            "is_reply": op == 2,
            "is_request": op == 1
        }

    @staticmethod
    def parse_ipv4(buf):
        if len(buf) < 20:
            return None
        v_ihl = buf[0]
        ihl = (v_ihl & 0x0F) * 4
        if len(buf) < ihl:
            return None

        tos, tot_len, ident, frag, ttl, proto, csum, src_ip, dst_ip = struct.unpack(
            "!BHHHBBH4s4s", buf[1:20]
        )
        return {
            "version": v_ihl >> 4,
            "ihl": ihl,
            "tos": tos,
            "total_len": tot_len,
            "ttl": ttl,
            "protocol": proto,
            "src_ip": socket.inet_ntoa(src_ip),
            "dest_ip": socket.inet_ntoa(dst_ip),
            "payload": buf[ihl:]
        }

    @staticmethod
    def parse_tcp(buf):
        if len(buf) < 20:
            return None
        sp, dp, seq, ack, off_res, flags, win, csum, urg = struct.unpack(
            "!HHIIBBHHH", buf[:20]
        )
        data_off = (off_res >> 4) * 4
        if len(buf) < data_off:
            return None

        return {
            "src_port": sp,
            "dest_port": dp,
            "seq": seq,
            "ack": ack,
            "offset": data_off,
            "flags": {
                "URG": bool(flags & 0x20),
                "ACK": bool(flags & 0x10),
                "PSH": bool(flags & 0x08),
                "RST": bool(flags & 0x04),
                "SYN": bool(flags & 0x02),
                "FIN": bool(flags & 0x01)
            },
            "raw_flags": flags,
            "is_null_scan": flags == 0,
            "is_fin_scan": flags == 0x01,
            "is_xmas_scan": bool(flags & 0x20 and flags & 0x08 and flags & 0x01),
            "is_syn_only": flags == 0x02,
            "payload": buf[data_off:]
        }

    @staticmethod
    def parse_udp(buf):
        if len(buf) < 8:
            return None
        sp, dp, length, csum = struct.unpack("!HHHH", buf[:8])
        return {
            "src_port": sp,
            "dest_port": dp,
            "length": length,
            "payload": buf[8:length] if length <= len(buf) else buf[8:]
        }

    @staticmethod
    def parse_dns_query(buf):
        if len(buf) < 12:
            return None
        try:
            # QDCOUNT is offset 4..6
            q_count = struct.unpack("!H", buf[4:6])[0]
            if q_count < 1:
                return None

            cursor = 12
            labels = []
            while cursor < len(buf):
                size = buf[cursor]
                if size == 0:
                    break
                # Handle DNS label pointer compression
                if (size & 0xC0) == 0xC0:
                    cursor += 2
                    break
                cursor += 1
                if cursor + size > len(buf):
                    break
                labels.append(buf[cursor:cursor + size].decode("ascii", errors="ignore"))
                cursor += size

            return ".".join(labels) if labels else None
        except Exception:
            return None

    @staticmethod
    def parse_http(buf):
        try:
            text = buf.decode("utf-8", errors="ignore")
            lines = text.split("\r\n")
            if not lines:
                return None

            first = lines[0].strip()
            verbs = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")
            if not any(first.startswith(v) for v in verbs):
                return None

            tokens = first.split()
            verb = tokens[0] if tokens else "UNKNOWN"
            path = tokens[1] if len(tokens) > 1 else "/"

            hdrs = {}
            body_chunks = []
            in_body = False

            for line in lines[1:]:
                if in_body:
                    body_chunks.append(line)
                elif not line:
                    in_body = True
                elif ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()

            return {
                "method": verb,
                "uri": path,
                "headers": hdrs,
                "body": "\n".join(body_chunks).strip()
            }
        except Exception:
            return None
