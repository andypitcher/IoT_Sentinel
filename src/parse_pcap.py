#!/usr/bin/env python
'''

    Iot Sentinel

'''

import datetime
import time
import dpkt
import sys
import socket
import pandas
import numpy as np
import glob, os
from struct import *


"""
    Features applied to each packet %12
    
    f= 0 or 1

    f= number of new destination ip address

    f= port class ref 0 or 1 0r 2 or 3
        
"""

def ip_to_str(address):
    """Print out an IP address given a string
    """
    return socket.inet_ntop(socket.AF_INET, address)


def port_class_def(ip_port):
    """
        no port => 0
        well known port [0,1023] => 1
        registered port [1024,49151] => 2
        dynamic port [49152,65535] => 3
    """

    if 0 <= ip_port <= 1023:
        return 1
    elif  1024 <= ip_port <= 49151 :
        return 2
    elif 49152 <= ip_port <= 65535 :
        return 3
    else:
        return 0



def get_dest_ip_counter(L3_ip_dst_new):

    global L3_ip_dst_counter

    if L3_ip_dst_new not in L3_ip_dst_set:
        L3_ip_dst_set.append(L3_ip_dst_new)
        L3_ip_dst_counter = L3_ip_dst_counter + 1
    else:
        pass
        #print L3_ip_dst_set

    return L3_ip_dst_set,L3_ip_dst_counter





packet_number = 0
L3_ip_dst_set = []


def parse_pcap(capture,device_label):
    
    global packet_number

    i_counter=0
    f = open(capture)
    pcap = dpkt.pcap.Reader(f)


    for ts, buf in pcap:

    #Variables assignment

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
        ip_add_count = 0

        port_class_src = 0
        port_class_dst = 0

        pck_size = 0
        pck_rawdata = 'n/a'

        
        i_counter+=1
        
        #Assign ethernet buffer value to eth
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        

        #Network Layer IP
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            L3_ip = 1

            #Get packet size
            pck_size = len(ip.data)

            #Check router alert (HL has to be above 5 and ip.opts == '\x94\x04\x00\x00')
            if ip.hl > 5:
                if ip.opts == dpkt.ip.IP_OPT_RALERT:
                    ip_ralert=1

            #Check new destination IP
            ip_dst_new=ip_to_str(ip.dst)
            L3_ip_dst,L3_ip_dst_count=get_dest_ip_counter(ip_dst_new)

            #print ("DST count: ",L3_ip_dst_count)
            print ("DST IP: ",L3_ip_dst)

            tcp = ip.data
            udp = ip.data
            
        #Network Layer ICMP-ICMP6     
            if type(ip.data) == dpkt.icmp.ICMP:
                L3_icmp = 1
            if type(ip.data) == dpkt.icmp6.ICMP6:
                L3_icmp6 = 1
            if type(ip.data) == dpkt.ip.IP_PROTO_RAW:
                pck_rawdata = 1
        
        #Transport UDP DHCP-DNS-MDNS-SSDP-NTP
            if type(ip.data) == dpkt.udp.UDP:
                L4_udp = 1
                port_class_src = port_class_def(udp.sport)
                port_class_dst = port_class_def(udp.dport)

                if udp.sport == 68 or udp.sport == 67 :
                    L7_dhcp = 1
                    L7_bootp = 1
                if udp.sport == 53 or udp.dport == 53 :
                    L7_dns = 1
                if udp.sport == 5353 or udp.dport == 5353 :
                    L7_mdns = 1
                if udp.sport == 1900 or udp.dport == 1900 :
                    L7_ssdp = 1
                if udp.sport == 123 or udp.dport == 123 :
                    L7_ntp = 1
        
        #Transport TCP HTTP-HTTPS
            if type(ip.data) == dpkt.tcp.TCP:
                L4_tcp = 1
                port_class_src = port_class_def(tcp.sport)
                port_class_dst = port_class_def(tcp.dport)

                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:
                        request = dpkt.http.Request(tcp.data)
                        L7_http = 1
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        continue                
                if tcp.dport == 443 and len(tcp.data) > 0:
                     L7_https = 1

        elif eth.type != dpkt.ethernet.ETH_TYPE_IP:
        
        #Data Link ARP-LLC
            if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                L2_arp = 1            
            if eth.type == dpkt.llc.LLC:
                L2_llc= 1
        
        #Network EAPoL
            if eth.type == dpkt.ethernet.ETH_TYPE_EAPOL:
                L3_eapol = 1
        else:
            print (i,'\n\nNon IP Packet type not supported  %s\n') % eth.data.__class__.__name__
            continue

    #Create the array containing the 23 features
        L3_ip_dst_counter=3

        ar = np.array([L2_arp,L2_llc,L3_eapol,L3_ip,pck_size,pck_rawdata,ip_padding,ip_ralert,L3_ip_dst_counter,port_class_src,port_class_dst,L3_icmp,L3_icmp6,L4_tcp,L4_udp,L7_https,L7_dhcp,L7_bootp,L7_ssdp,L7_dns,L7_mdns,L7_ntp,device_label])
        df = pandas.DataFrame(ar, columns = [i_counter], index  = ['arp', 'llc', 'eapol', 'ip','pck_size','pck_rawdata','ip_padding','ip_ralert','ip_add_count','portc_src','portc_dst','icmp','icmp6','tcp','udp','http','dhcp','bootp','ssdp','dns','mdns','ntp','device_label'])
        print (df)
        csv_file='csv_results/file_'+device_label+'_'+str(packet_number)+'.csv'
        df.to_csv(csv_file, sep='\t', encoding='utf-8')
        print ("\n")
        packet_number+=1
    f.close()


def main():

    global L3_ip_dst_counter 

    device_label=os.listdir('/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/')
    i = 0
    while i < len(device_label):
        filename_path='/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/captures_IoT_Sentinel/captures_IoT-Sentinel/'+device_label[i]+'/*.pcap'
        # filename_path='/home/andyp/Documents/Studies/CONCORDIA/IoT_project/IoT_Sentinel/src/test_pcap/*.pcap'
        for filename in glob.glob(filename_path):
            if os.path.isfile(filename):
                del L3_ip_dst_set[:]
                L3_ip_dst_counter = 1 
                print (L3_ip_dst_set,L3_ip_dst_counter)
                parse_pcap(filename,device_label[i])
            else:
                print('file does not exist')
        i += 1


if __name__== "__main__":
  main()