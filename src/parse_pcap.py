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

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)



#f = open('/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-2-STA.pcap')
f = open(str(sys.argv[1]))
pcap = dpkt.pcap.Reader(f)

i=0

for ts, buf in pcap:

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

    
    i+=1
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    #Data Link ARP-LLC
    if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        L2_arp = 1
        #print 'ARP'
    elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
        print i,'\n\nNon IP Packet type not supported (EAPOL ?) %s\n' % eth.data.__class__.__name__
        continue
    else:
        L2_arp = 0

    if eth.type == dpkt.llc.LLC:
        L2_llc= 1
    else:
        L2_llc = 0

    #Network IP-ICMP-ICMP6-EAPOL
    #if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        #print 'EAPOL'
    #    L3_eapol = 1
    #else:
    #    L3_eapol = 0

    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        L3_ip = 1
    else:
        L3_ip = 0

    if type(ip.data) == dpkt.icmp.ICMP:
        L3_icmp = 1
    else:
        L3_icmp = 0

    if type(ip.data) == dpkt.icmp6.ICMP6:
        L3_icmp6 = 1
    else:
        L3_icmp6 = 0

    
    #TCP-UDP
    if type(ip.data) == dpkt.udp.UDP:
        L4_udp = 1
        #if udp.dport == 67 or udp.dport == 68:
        #    L7_dhcp = 1
    else:
        L4_udp = 0
    if type(ip.data) == dpkt.tcp.TCP:
        L4_tcp = 1
        if tcp.dport == 80:
            L7_http = 1
        elif tcp.dport == 443:
            L7_https = 1
    else:
        L4_tcp = 0  

    #Application http-https-dhcp-bootp-ssdp-dns-mdns-ntp
    
    tcp = ip.data
    udp = ip.data    

    #port = tcp.dport

    

    #elif type(ip.data) == dpkt.dhcp.DHCP:
    #    L7_dhcp = 1
    #    continue
    #elif type(udp.data) == dpkt.dhcp.DHCP:
    #    L7_dhcp = 1
    #    continue

    #print type(ip.data)
    print "----------"
    print i
    #print 'ip_address_src= ',ip_to_str(ip.src) 
    print "L2 properties:"
    print "ARP: ",L2_arp
    print "LLC: ",L2_llc
    print "L3 properties:"
    print "EAPOL: ",str(L3_eapol)
    print "IP: ",L3_ip
    print "ICMP: ",L3_icmp
    print "ICMP6: ",L3_icmp6
    print "L4 properties:"
    print "TCP: ",L4_tcp
    print "UDP: ",L4_udp
    print "L7 properties:"
    print "HTTP: ",L7_http
    print "HTTPS: ",L7_https
    print "DHCP: ",L7_dhcp
    print "BOOTP: ",L7_bootp
    print "SSDP: ",L7_ssdp
    print "DNS: ",L7_dns
    print "MDNS: ",L7_mdns
    print "NTP: ",L7_ntp


    #print 'ip_address_src= ',ip_to_str(ip.src)
    #print 'ip_address_dst= ',ip_to_str(ip.dst)
    #print 'tcp_sum=',tcp.sum
    #print 'tcp_sport=',tcp.sport
    #print 'tcp_dport=',tcp.dport
    #print '--------'
#
f.close()
