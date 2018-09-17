# IoT_Sentinel

This program is an implementation of IoT sentinel: https://arxiv.org/pdf/1611.04880.pdf
Device Fingerprint, it takes as input pcaps and tests each packets against 23 features:




Usage:  parse_pcap.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>
Example: ./parse_pcap.py -d captures_IoT_Sentinel/captures_IoT-Sentinel/ -o csv_result_full/
