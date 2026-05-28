import dpkt

from iot_fingerprint import (
    PACKET_FEATURE_HEADERS,
    DestinationTracker,
    aggregate_packet_rows,
    extract_packet_features,
    port_class_def,
)


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


def _packet_row(value: int, label: str = "camera"):
    row = {feature: 0 for feature in PACKET_FEATURE_HEADERS}
    row["Pck_size"] = value
    row["Label"] = label
    return row


def test_aggregate_packet_rows_exact_multiple_no_padding():
    rows = [_packet_row(index) for index in range(1, 25)]
    aggregated = aggregate_packet_rows(rows, "camera", window_size=12)

    assert len(aggregated) == 2
    assert aggregated[0]["Pck_size_1"] == 1
    assert aggregated[0]["Pck_size_12"] == 12
    assert aggregated[1]["Pck_size_1"] == 13
    assert aggregated[1]["Pck_size_12"] == 24
    assert aggregated[0]["Label"] == "camera"


def test_aggregate_packet_rows_adds_zero_padding_for_short_window():
    rows = [_packet_row(index) for index in range(1, 6)]
    aggregated = aggregate_packet_rows(rows, "camera", window_size=12)

    assert len(aggregated) == 1
    assert aggregated[0]["Pck_size_5"] == 5
    assert aggregated[0]["Pck_size_6"] == 0
    assert aggregated[0]["TCP_12"] == 0


def test_aggregate_packet_rows_empty_input():
    assert aggregate_packet_rows([], "camera", window_size=12) == []


def test_aggregate_packet_rows_single_packet():
    aggregated = aggregate_packet_rows([_packet_row(9)], "camera", window_size=12)

    assert len(aggregated) == 1
    assert aggregated[0]["Pck_size_1"] == 9
    assert aggregated[0]["Pck_size_2"] == 0
    assert aggregated[0]["NTP_12"] == 0
