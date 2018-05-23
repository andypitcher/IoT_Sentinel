#!/usr/bin/env python

import dpkt

f = open('/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-1-STA.pcap')
pcap = dpkt.pcap.Reader(f)

#for ts, buf in pcap:
#    print ts, len(buf)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    print ts, eth
    print '--------'


f.close()
