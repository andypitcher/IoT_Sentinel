"""End-to-end tests for the IoT Sentinel fingerprinting pipeline.

These tests run the full pipeline against a small subset of real pcap captures
and verify the output matches expected results.
"""

import os
from pathlib import Path

import dpkt
import pandas as pd

from iot_fingerprint import AGGREGATION_WINDOW, FEATURE_HEADERS, aggregation_headers, run

FIXTURES_DIR = Path(__file__).parent / "fixtures"
E2E_CAPTURES = FIXTURES_DIR / "e2e_captures"
E2E_EXPECTED = FIXTURES_DIR / "e2e_expected"

NUM_FEATURES = len(FEATURE_HEADERS)


def _load_csv(path: Path) -> pd.DataFrame:
    """Load a tab-separated feature CSV without headers."""
    return pd.read_csv(path, sep="\t", header=None, names=FEATURE_HEADERS)


class TestE2EDirectoryMode:
    """E2E tests running the pipeline in directory mode (-d)."""

    def test_pipeline_produces_expected_device_folders(self, tmp_path):
        """Pipeline creates one output folder per device in the input directory."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        output_devices = sorted(os.listdir(tmp_path))
        expected_devices = sorted(os.listdir(E2E_EXPECTED))
        assert output_devices == expected_devices

    def test_pipeline_produces_correct_number_of_csv_files(self, tmp_path):
        """Pipeline creates one CSV per pcap file per device."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(E2E_EXPECTED):
            expected_files = sorted(os.listdir(E2E_EXPECTED / device))
            actual_files = sorted(os.listdir(tmp_path / device))
            assert actual_files == expected_files, f"Mismatch for device {device}"

    def test_pipeline_output_matches_expected_row_counts(self, tmp_path):
        """Each output CSV has the expected number of rows (one per packet)."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(E2E_EXPECTED):
            for csv_file in os.listdir(E2E_EXPECTED / device):
                expected_df = _load_csv(E2E_EXPECTED / device / csv_file)
                actual_df = _load_csv(tmp_path / device / csv_file)
                assert len(actual_df) == len(expected_df), (
                    f"Row count mismatch for {device}/{csv_file}: "
                    f"expected {len(expected_df)}, got {len(actual_df)}"
                )

    def test_pipeline_output_has_correct_columns(self, tmp_path):
        """Output CSVs have exactly 23 feature columns."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(tmp_path):
            for csv_file in os.listdir(tmp_path / device):
                df = _load_csv(tmp_path / device / csv_file)
                assert len(df.columns) == NUM_FEATURES, (
                    f"Column count mismatch for {device}/{csv_file}"
                )

    def test_pipeline_output_labels_match_device_name(self, tmp_path):
        """The Label column in each CSV matches the device folder name."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(tmp_path):
            for csv_file in os.listdir(tmp_path / device):
                df = _load_csv(tmp_path / device / csv_file)
                assert (df["Label"] == device).all(), (
                    f"Label mismatch in {device}/{csv_file}"
                )

    def test_pipeline_output_matches_expected_content(self, tmp_path):
        """Full content comparison: output matches expected CSVs exactly."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(E2E_EXPECTED):
            for csv_file in os.listdir(E2E_EXPECTED / device):
                expected_df = _load_csv(E2E_EXPECTED / device / csv_file)
                actual_df = _load_csv(tmp_path / device / csv_file)
                pd.testing.assert_frame_equal(
                    actual_df, expected_df,
                    check_dtype=False,
                    obj=f"{device}/{csv_file}",
                )

    def test_pipeline_feature_values_are_valid(self, tmp_path):
        """All binary feature columns contain only 0 or 1 values."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        binary_features = [
            "ARP", "LLC", "EAPOL", "IP_padding", "IP_ralert",
            "ICMP", "ICMP6", "TCP", "UDP", "HTTPS", "HTTP",
            "DHCP", "BOOTP", "SSDP", "DNS", "MDNS", "NTP", "Pck_rawdata",
        ]

        for device in os.listdir(tmp_path):
            for csv_file in os.listdir(tmp_path / device):
                df = _load_csv(tmp_path / device / csv_file)
                for feat in binary_features:
                    values = df[feat].unique()
                    assert set(values).issubset({0, 1}), (
                        f"Non-binary value in {feat} for {device}/{csv_file}: {values}"
                    )

    def test_pipeline_port_class_values_are_valid(self, tmp_path):
        """Port class columns contain only values 0-3."""
        run(["-d", str(E2E_CAPTURES), "-o", str(tmp_path)])

        for device in os.listdir(tmp_path):
            for csv_file in os.listdir(tmp_path / device):
                df = _load_csv(tmp_path / device / csv_file)
                for col in ["Portcl_src", "Portcl_dst"]:
                    values = df[col].unique()
                    assert set(values).issubset({0, 1, 2, 3}), (
                        f"Invalid port class in {col} for {device}/{csv_file}: {values}"
                    )


class TestE2ESingleFileMode:
    """E2E tests running the pipeline in single file mode (-i)."""

    def test_single_pcap_produces_valid_output(self, tmp_path):
        """Processing a single pcap produces correct output."""
        pcap_file = str(E2E_CAPTURES / "Aria" / "Setup-A-1-STA.pcap")
        run(["-i", pcap_file, "-l", "Aria", "-o", str(tmp_path)])

        output_files = list((tmp_path / "Aria").glob("*.csv"))
        assert len(output_files) == 1

        df = _load_csv(output_files[0])
        expected_df = _load_csv(E2E_EXPECTED / "Aria" / "file_Aria_0.csv")

        assert len(df) == len(expected_df)
        assert (df["Label"] == "Aria").all()

    def test_single_pcap_content_matches_directory_mode(self, tmp_path):
        """Single file mode produces same features as directory mode for same input."""
        pcap_file = str(E2E_CAPTURES / "Aria" / "Setup-A-1-STA.pcap")
        run(["-i", pcap_file, "-l", "Aria", "-o", str(tmp_path)])

        output_files = list((tmp_path / "Aria").glob("*.csv"))
        actual_df = _load_csv(output_files[0])
        expected_df = _load_csv(E2E_EXPECTED / "Aria" / "file_Aria_0.csv")

        pd.testing.assert_frame_equal(
            actual_df, expected_df,
            check_dtype=False,
            obj="Single file mode vs expected",
        )

    def test_single_pcap_aggregate_flag_outputs_fixed_window_csv(self, tmp_path):
        """Aggregate mode outputs one fixed-size fingerprint with zero-padding."""
        pcap_path = tmp_path / "single_packet.pcap"
        with pcap_path.open("wb") as pcap_file:
            writer = dpkt.pcap.Writer(pcap_file)
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
            writer.writepkt(bytes(eth))

        run(["-i", str(pcap_path), "-l", "camera", "-o", str(tmp_path), "--aggregate"])
        output_files = list((tmp_path / "camera").glob("*.csv"))
        assert len(output_files) == 1

        headers = aggregation_headers(AGGREGATION_WINDOW)
        df = pd.read_csv(output_files[0], sep="\t", header=None, names=headers)
        assert df.shape == (1, ((len(FEATURE_HEADERS) - 1) * AGGREGATION_WINDOW) + 1)
        assert df["Label"].iloc[0] == "camera"
        assert df["TCP_1"].iloc[0] == 1
        assert df["HTTP_1"].iloc[0] == 1
        assert df["TCP_2"].iloc[0] == 0
