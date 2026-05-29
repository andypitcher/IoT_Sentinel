# IoT_Sentinel

> Note: This project is originally from **2017** and has been modernized for Python 3 compatibility.

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



Usage:  
```
iot_fingerprint.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>  
Example: ./iot-fingerprint.py -d captures_IoT_Sentinel/captures_IoT-Sentinel/ -o csv_result_full/
```

## Installation

```bash
pip install -r requirements.txt
```

## Run

**Process a directory of pcap captures (one subfolder per device):**
```bash
python iot_fingerprint.py -d captures_IoT_Sentinel/captures_IoT-Sentinel/ -o csv_results/
```

**Process a single pcap file with a device label:**
```bash
python iot_fingerprint.py -i path/to/capture.pcap -l "smart_camera" -o csv_results/
```

**Enable packet aggregation (12-packet default window):**
This follows the IoT Sentinel fingerprint-construction approach described in the paper (arXiv:1611.04880), where packet features are grouped into fixed-size windows.
```bash
python iot_fingerprint.py -i path/to/capture.pcap -l "smart_camera" -o csv_results/ --aggregate
```

**Customize aggregation window size:**
```bash
python iot_fingerprint.py -i path/to/capture.pcap -l "smart_camera" -o csv_results/ --aggregate --window-size 24
```

**Using Docker:**
```bash
docker build -t iot-sentinel .
docker run --rm -v $(pwd)/captures:/data/captures -v $(pwd)/output:/data/output \
  iot-sentinel -d /data/captures/ -o /data/output/
```

## Testing

```bash
pytest
```
