import os
import struct
import time

class PcapWriter:
    """Zero-dependency Wireshark-compatible PCAP file writer (libpcap format)."""

    def __init__(self, filepath, linktype=1):
        """
        linktype=1: LINKTYPE_ETHERNET (standard Ethernet frame)
        linktype=101: LINKTYPE_RAW (raw IPv4 packets)
        """
        self.filepath = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        self.linktype = linktype
        self.file = None
        self._init_pcap()

    def _init_pcap(self):
        """Writes the 24-byte PCAP Global Header."""
        self.file = open(self.filepath, "wb")
        # Global Header:
        # magic_number (uint32) 0xa1b2c3d4
        # version_major (uint16) 2
        # version_minor (uint16) 4
        # thiszone (int32) 0
        # sigfigs (uint32) 0
        # snaplen (uint32) 65535
        # network (uint32) linktype (1 = Ethernet)
        global_header = struct.pack(
            "=IHHiIII",
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.linktype
        )
        self.file.write(global_header)
        self.file.flush()

    def write_packet(self, packet_bytes, timestamp=None):
        """Appends a 16-byte packet header followed by the raw packet bytes."""
        if not self.file or self.file.closed:
            return

        ts = timestamp or time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        pkt_len = len(packet_bytes)

        # Packet Header:
        # ts_sec (uint32), ts_usec (uint32), incl_len (uint32), orig_len (uint32)
        pkt_header = struct.pack("=IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self.file.write(pkt_header)
        self.file.write(packet_bytes)
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()
