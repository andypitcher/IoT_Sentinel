#!/usr/bin/env python3
"""
IoT Sentinel
Author: Andy Pitcher (@andypitcher)

This program is an implementation of IoT sentinel: https://arxiv.org/pdf/1611.04880.pdf

Device Fingerprint, it takes as input pcaps and tests each packets against 23 features:

    Link layer protocol (2)                 ARP/LLC
    Network layer protocol (4)              IP/ICMP/ICMPv6/EAPoL
    Transport layer protocol (2)            TCP/UDP
    Application layer protocol (8)          HTTP/HTTPS/DHCP/BOOTP/SSDP/DNS/MDNS/ NTP
    IP options (2)                          Padding/RouterAlert
    Packet content (2)                      Size (int)/Raw data
    IP address (1)                          Destination IP counter (int)
    Port class (2)                          Source (int) / Destination (int)

Usage:  iot_fingerprint.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>
Example: ./iot_fingerprint.py -d captures_IoT_Sentinel/captures_IoT-Sentinel/ -o csv_result_full/
"""

from __future__ import annotations

import argparse
import glob
import os
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import dpkt
import pandas as pd

ETH_TYPE_EAPOL = 0x888E
IP_OPT_RALERT = 0x94  # Router Alert option type (not available in all dpkt versions)

FEATURE_HEADERS = [
    "ARP",
    "LLC",
    "EAPOL",
    "Pck_size",
    "Pck_rawdata",
    "IP_padding",
    "IP_ralert",
    "IP_add_count",
    "Portcl_src",
    "Portcl_dst",
    "ICMP",
    "ICMP6",
    "TCP",
    "UDP",
    "HTTPS",
    "HTTP",
    "DHCP",
    "BOOTP",
    "SSDP",
    "DNS",
    "MDNS",
    "NTP",
    "Label",
]


@dataclass
class DestinationTracker:
    """Track unique destination IPs for a pcap stream."""

    seen: set[str] = field(default_factory=set)

    def add(self, destination_ip: str) -> int:
        """Add destination IP and return current unique destination count."""
        self.seen.add(destination_ip)
        return len(self.seen)


def create_outputdir(outputdir: str, device_label: str) -> Path:
    """Create output directory for a device label."""
    dirpath = Path(outputdir) / device_label
    dirpath.mkdir(parents=True, exist_ok=True)
    return dirpath


def ip_to_str(address: bytes) -> str:
    """Convert packed IP address bytes to a string."""
    return socket.inet_ntop(socket.AF_INET, address)


def port_class_def(ip_port: int) -> int:
    """Classify a port number into IoT Sentinel's expected classes."""
    if 0 <= ip_port <= 1023:
        return 1
    if 1024 <= ip_port <= 49151:
        return 2
    if 49152 <= ip_port <= 65535:
        return 3
    return 0


def extract_packet_features(
    buf: bytes,
    device_label: str,
    destination_tracker: DestinationTracker,
) -> Optional[Dict[str, int | str]]:
    """Extract feature dictionary for one packet buffer.

    Returns None for malformed packets.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.UnpackError, ValueError):
        return None

    row: Dict[str, int | str] = {
        "ARP": 0,
        "LLC": 0,
        "EAPOL": 0,
        "Pck_size": 0,
        "Pck_rawdata": 0,
        "IP_padding": 0,
        "IP_ralert": 0,
        "IP_add_count": 0,
        "Portcl_src": 0,
        "Portcl_dst": 0,
        "ICMP": 0,
        "ICMP6": 0,
        "TCP": 0,
        "UDP": 0,
        "HTTPS": 0,
        "HTTP": 0,
        "DHCP": 0,
        "BOOTP": 0,
        "SSDP": 0,
        "DNS": 0,
        "MDNS": 0,
        "NTP": 0,
        "Label": device_label,
    }

    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        row["Pck_size"] = len(ip.data)

        has_router_alert = (
            hasattr(ip, "hl")
            and ip.hl > 5
            and hasattr(ip, "opts")
            and ip.opts == IP_OPT_RALERT
        )
        if has_router_alert:
            row["IP_ralert"] = 1

        try:
            row["IP_add_count"] = destination_tracker.add(ip_to_str(ip.dst))
        except (ValueError, OSError):
            row["IP_add_count"] = len(destination_tracker.seen)

        if isinstance(ip.data, dpkt.icmp.ICMP):
            row["ICMP"] = 1
        if isinstance(ip.data, dpkt.icmp6.ICMP6):
            row["ICMP6"] = 1
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            row["UDP"] = 1
            row["Portcl_src"] = port_class_def(udp.sport)
            row["Portcl_dst"] = port_class_def(udp.dport)
            if udp.sport in (67, 68):
                row["DHCP"] = 1
                row["BOOTP"] = 1
            if 53 in (udp.sport, udp.dport):
                row["DNS"] = 1
            if 5353 in (udp.sport, udp.dport):
                row["MDNS"] = 1
            if 1900 in (udp.sport, udp.dport):
                row["SSDP"] = 1
            if 123 in (udp.sport, udp.dport):
                row["NTP"] = 1

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            row["TCP"] = 1
            row["Portcl_src"] = port_class_def(tcp.sport)
            row["Portcl_dst"] = port_class_def(tcp.dport)
            if 80 in (tcp.sport, tcp.dport):
                row["HTTP"] = 1
            if 443 in (tcp.sport, tcp.dport):
                row["HTTPS"] = 1

        if ip.p == dpkt.ip.IP_PROTO_RAW or isinstance(ip.data, (bytes, bytearray)):
            row["Pck_rawdata"] = 1

    elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            row["ARP"] = 1
        if isinstance(eth.data, dpkt.llc.LLC):
            row["LLC"] = 1
        if eth.type == ETH_TYPE_EAPOL:
            row["EAPOL"] = 1

    return row


def write_csv(outputdir: str, device_label: str, id_pcap: int, rows: List[Dict[str, int | str]]) -> None:
    """Write extracted rows once per pcap file."""
    if not rows:
        return
    out_dir = create_outputdir(outputdir, device_label)
    csv_file = out_dir / f"file_{device_label}_{id_pcap}.csv"
    pd.DataFrame(rows, columns=FEATURE_HEADERS).to_csv(
        csv_file,
        sep="\t",
        encoding="utf-8",
        index=False,
        header=False,
    )


def parse_pcap(outputdir: str, capture: str, device_label: str, id_pcap: int) -> None:
    """Parse one pcap and persist extracted features."""
    rows: List[Dict[str, int | str]] = []
    tracker = DestinationTracker()

    try:
        with Path(capture).open("rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for _, buf in pcap:
                row = extract_packet_features(buf, device_label, tracker)
                if row is not None:
                    rows.append(row)
    except (OSError, ValueError, dpkt.UnpackError, dpkt.NeedData) as exc:
        print(f"Skipping unreadable pcap '{capture}': {exc}")
        return

    write_csv(outputdir, device_label, id_pcap, rows)


def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="IoT_Sentinel parse_pcap v1.0")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("-d", "--dir", dest="inputdir", help="Input directory containing device subfolders")
    source_group.add_argument("-i", "--ifile", dest="inputpcap", help="Single input pcap file")
    parser.add_argument("-o", "--odir", dest="outputdir", required=True, help="Output directory")
    parser.add_argument("-l", "--label", dest="label", help="Device label for single pcap mode")

    args = parser.parse_args(argv)
    if args.inputpcap and not args.label:
        parser.error("-l/--label is required when using -i/--ifile")

    return args


def run(argv: List[str]) -> int:
    """CLI entrypoint returning process exit code."""
    args = parse_args(argv)
    print("IoT_Sentinel: parse_pcap.py v1.0\n")

    if args.inputdir:
        device_labels = os.listdir(args.inputdir)
        for device_label in device_labels:
            filename_path = os.path.join(args.inputdir, device_label, "*.pcap")
            print(f"\nINPUTDIR: {args.inputdir}")
            print(f"\nOUTPUTDIR: {args.outputdir}")
            print(f"\nDEVICE TESTED:\n{device_labels}\n")
            print("\nSTARTING...\n")
            id_pcap = 0
            for filename in glob.glob(filename_path):
                if os.path.isfile(filename):
                    print(f"Device: {device_label}\n")
                    parse_pcap(args.outputdir, filename, device_label, id_pcap)
                    id_pcap += 1
                else:
                    print("file does not exist")
    else:
        print(f"\nINPUTPCAP: {args.inputpcap}")
        print(f"\nOUTPUTDIR: {args.outputdir}")
        print(f"\nDEVICE TESTED:\n[{args.label}]")
        print("\nSTARTING...\n")
        parse_pcap(args.outputdir, args.inputpcap, args.label, 1)

    return 0


def main() -> None:
    """Script entry point."""
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
