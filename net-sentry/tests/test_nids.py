import os
import sys
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from net_sentry.parser import PacketParser
from net_sentry.detector import NetworkDetector, calculate_shannon_entropy
from net_sentry.pcap_writer import PcapWriter
from net_sentry.simulator import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_tcp_segment,
    build_arp_packet,
    build_udp_datagram,
    build_dns_query
)

class TestNetSentry(unittest.TestCase):
    def setUp(self):
        self.detector = NetworkDetector({
            "port_scan_threshold_ports": 5,
            "port_scan_window_seconds": 2.0,
            "syn_flood_threshold_packets": 10,
            "dns_entropy_threshold": 3.5,
            "dns_length_threshold": 30
        })

    def test_shannon_entropy(self):
        """Verifies Shannon entropy calculation."""
        low_entropy = calculate_shannon_entropy("aaaaaaaaaa")
        self.assertAlmostEqual(low_entropy, 0.0, places=1)

        normal_domain = calculate_shannon_entropy("google.com")
        self.assertLess(normal_domain, 3.2)

        high_entropy = calculate_shannon_entropy("4f9a2b8c1e7d0f3a5b6c7d8e9f0a1b2c")
        self.assertGreater(high_entropy, 3.5)

    def test_stealth_xmas_scan_detection(self):
        """Verifies detection of TCP XMAS scan (FIN+PSH+URG)."""
        tcp_bytes = build_tcp_segment(50000, 80, flags=0x29)  # URG + PSH + FIN
        parsed_tcp = PacketParser.parse_tcp(tcp_bytes)
        self.assertTrue(parsed_tcp["is_xmas_scan"])

        ip_pkt = {"src_ip": "10.0.0.1", "dest_ip": "192.168.1.10"}
        alert = self.detector.evaluate_tcp(ip_pkt, parsed_tcp)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "STEALTH_SCAN_TCP_XMAS")

    def test_stealth_null_scan_detection(self):
        """Verifies detection of TCP NULL scan (zero flags)."""
        tcp_bytes = build_tcp_segment(50000, 80, flags=0x00)
        parsed_tcp = PacketParser.parse_tcp(tcp_bytes)
        self.assertTrue(parsed_tcp["is_null_scan"])

        ip_pkt = {"src_ip": "10.0.0.1", "dest_ip": "192.168.1.10"}
        alert = self.detector.evaluate_tcp(ip_pkt, parsed_tcp)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "STEALTH_SCAN_TCP_NULL")

    def test_port_scan_sweep_detection(self):
        """Verifies port scan detection after exceeding threshold."""
        ip_pkt = {"src_ip": "10.0.0.50", "dest_ip": "192.168.1.10"}
        alert = None
        for port in [21, 22, 23, 25, 80, 443]:
            tcp_bytes = build_tcp_segment(40000 + port, port, flags=0x02)
            parsed_tcp = PacketParser.parse_tcp(tcp_bytes)
            alert = self.detector.evaluate_tcp(ip_pkt, parsed_tcp)
            if alert:
                break

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "PORT_SCAN_RECON_SWEEP")

    def test_arp_cache_poisoning_detection(self):
        """Verifies detection of duplicate MAC conflict (ARP Poisoning)."""
        # Baseline legitimate ARP
        legit_arp = build_arp_packet(2, "00:11:22:33:44:55", "192.168.1.1", "ff:ff:ff:ff:ff:ff", "192.168.1.10")
        parsed_legit = PacketParser.parse_arp(legit_arp)
        alert1 = self.detector.evaluate_arp(parsed_legit)
        self.assertIsNone(alert1)

        # Attacker claims same IP with different MAC
        spoof_arp = build_arp_packet(2, "de:ad:be:ef:aa:bb", "192.168.1.1", "ff:ff:ff:ff:ff:ff", "192.168.1.10")
        parsed_spoof = PacketParser.parse_arp(spoof_arp)
        alert2 = self.detector.evaluate_arp(parsed_spoof)
        self.assertIsNotNone(alert2)
        self.assertEqual(alert2.rule_name, "ARP_CACHE_POISONING_ATTACK")

    def test_dns_tunneling_detection(self):
        """Verifies detection of high-entropy DNS query exfiltration."""
        high_entropy_q = "NTRhNzM2OTY3NmU2MTZmMjA2NTc4NjY2OTZjLnBhc3N3b3Jkcw.c2.attacker.com"
        ip_pkt = {"src_ip": "192.168.1.25", "dest_ip": "8.8.8.8"}
        alert = self.detector.evaluate_dns(ip_pkt, high_entropy_q)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "DNS_TUNNELING_EXFILTRATION")

    def test_pcap_writer(self):
        """Verifies standard PCAP file creation and valid global header."""
        temp_dir = tempfile.mkdtemp()
        pcap_file = os.path.join(temp_dir, "test.pcap")
        try:
            writer = PcapWriter(pcap_file)
            test_pkt = b"\x00" * 64
            writer.write_packet(test_pkt)
            writer.close()

            self.assertTrue(os.path.exists(pcap_file))
            with open(pcap_file, "rb") as f:
                header = f.read(24)
                # Verify magic number 0xa1b2c3d4 in little/big endian
                self.assertIn(header[:4], (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
