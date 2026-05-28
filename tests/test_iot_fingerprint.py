from pathlib import Path
import sys

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iot_fingerprint import DestinationTracker, extract_packet_features, port_class_def


def test_port_class_def_ranges():
    assert port_class_def(-1) == 0
    assert port_class_def(0) == 1
    assert port_class_def(1023) == 1
    assert port_class_def(1024) == 2
    assert port_class_def(49151) == 2
    assert port_class_def(49152) == 3
    assert port_class_def(65535) == 3
    assert port_class_def(70000) == 0


def test_destination_tracker_counts_uniques_once():
    tracker = DestinationTracker()
    assert tracker.add("192.168.0.1") == 1
    assert tracker.add("192.168.0.1") == 1
    assert tracker.add("192.168.0.2") == 2


def test_extract_packet_features_for_tcp_http_packet():
    ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP)
    ip.v = 4
    ip.hl = 5
    ip.ttl = 64
    ip.data = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, flags=dpkt.tcp.TH_SYN)
    eth = dpkt.ethernet.Ethernet(
        dst=b"\xaa\xaa\xaa\xaa\xaa\xaa",
        src=b"\xbb\xbb\xbb\xbb\xbb\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )

    row = extract_packet_features(bytes(eth), "camera", DestinationTracker())

    assert row is not None
    assert row["TCP"] == 1
    assert row["HTTP"] == 1
    assert row["IP_add_count"] == 1


def test_extract_packet_features_returns_none_for_malformed_packet():
    row = extract_packet_features(b"not-a-packet", "camera", DestinationTracker())
    assert row is None
