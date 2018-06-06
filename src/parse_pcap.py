#!/usr/bin/env python

import datetime
import dpkt
import sys
import socket

"""
    Features applied to each packet %12
    
    f= 0 or 1

    f= number of new destination ip address

    f= port class ref 0 or 1 0r 2 or 3

        no port => 0
        well known port [0,1023] => 1
        registered port [1024,49151] => 2
        dynamic port [49152,65535] => 3
        
"""

L2_arp = 0
L2_llc = 0

L3_ip = 0
L3_icmp = 0
L3_icmp6 = 0
L3_eapol = 0

L4_tcp = 0
L4_udp = 0

L7_http = 0
L7_https = 0
L7_dhcp = 0
L7_bootp = 0
L7_ssdp = 0
L7_dns = 0
L7_mdns = 0
L7_ntp = 0

ip_padding = 0
ip_ralert = 0
ip_address_counter = 0

port_class_src = 0
port_class_dst = 0

pck_size = 0
pck_rawdata = ''

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
    ip = eth.data
    
    if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        #print 'this is ARP: %s' %eth.data.__class__.__name__
        continue
    elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data
            #.__class__.__name__
            continue
    elif type(ip.data) == dpkt.icmp.ICMP:
        print 'This is ICMP'
        continue
    elif type(ip.data) == dpkt.dhcp.DHCP:
        print 'This is DHCP'
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
