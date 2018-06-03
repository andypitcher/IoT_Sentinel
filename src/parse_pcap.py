#!/usr/bin/env python

import datetime
import dpkt
import sys
import socket


#f = open('/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-2-STA.pcap')
f = open(str(sys.argv[1]))
pcap = dpkt.pcap.Reader(f)

i=1

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

for ts, buf in pcap:
    print i
    i+=1
    eth = dpkt.ethernet.Ethernet(buf)
    #print eth
    ip = eth.data
    #ip2 = dpkt.ip.IP(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue
    elif type(ip.data) == dpkt.icmp.ICMP:
        print 'This is ICMP'
        continue
    tcp = ip.data
    print type(ip.data)
    print 'ip_address_src= ',ip_to_str(ip.src)
    print 'ip_address_dst= ',ip_to_str(ip.dst)
    print 'tcp_sum=',tcp.sum
    print 'tcp_sport=',tcp.sport
    print 'tcp_dport=',tcp.dport
    print '--------'

#
f.close()
