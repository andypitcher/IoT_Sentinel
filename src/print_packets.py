#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
import datetime
import socket
from dpkt.ip import IP, IP_PROTO_UDP
from dpkt.udp import UDP


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




def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)


def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)


def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    i=0
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print '[%d] Timestamp: %s' %(i,str(datetime.datetime.utcfromtimestamp(timestamp)))
        i += 1
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        ip = dpkt.ip.IP(buf)
        if type(ip.data) == UDP :  # checking of type of data that was recognized by dpkg
            udp = ip.data
            print udp.sport
        else:
             print "Not UDP"
        #print dpkt.ethernet.ETH_TYPE_ARP
        #ip = dpkt.ip.IP(buf)
        #ip = dpkt.ip.IP(data)
        #ip = eth.data
        #ip_addr = socket.inet_ntoa(ip.src|ip.dst)
        #print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
        #print 'IP Packet type: %s' % eth.data.__class__.__name__
        #print 'IP type: %s' %eth.data.__class__.__name__
        #print 'ARP frame type: %s' %eth.data._class_   
        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue

        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)


def test():
    """Open up a test pcap file and print out the packets"""
    #f = open('/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-1-STA.pcap')
    with open('capture_test.pcap') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()
