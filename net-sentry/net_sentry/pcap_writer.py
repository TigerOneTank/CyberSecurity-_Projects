import os
import struct
import time

class PcapWriter:
    def __init__(self, out_path, linktype=1):
        self.out_path = os.path.abspath(out_path)
        os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
        self.linktype = linktype
        self.fh = None
        self._write_global_hdr()

    def _write_global_hdr(self):
        self.fh = open(self.out_path, "wb")
        # libpcap global header: magic, v_major(2), v_minor(4), thiszone, sigfigs, snaplen(65535), linktype
        hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype)
        self.fh.write(hdr)
        self.fh.flush()

    def write_packet(self, raw_pkt, epoch_ts=None):
        if not self.fh or self.fh.closed:
            return

        ts = epoch_ts or time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        sz = len(raw_pkt)

        # per-packet record header: ts_sec, ts_usec, incl_len, orig_len
        rec = struct.pack("=IIII", sec, usec, sz, sz)
        self.fh.write(rec + raw_pkt)
        self.fh.flush()

    def close(self):
        if self.fh and not self.fh.closed:
            self.fh.close()
