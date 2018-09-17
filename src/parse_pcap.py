#!/usr/bin/env python
'''

    Iot Sentinel: parse_pcap.py v1.0
    Author: Andy Pitcher <andy.pitcher@mail.concordia.ca>

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


Usage:  parse_pcap.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>
Example: ./parse_pcap.py -d captures_IoT_Sentinel/captures_IoT-Sentinel/ -o csv_result_full/

'''

import datetime
import time
import dpkt
import sys
import getopt
import socket
import pandas
import glob, os
from struct import *


"""
    Features applied to each packet %12
    
    f= 0 or 1

    f= number of new destination ip address

    f= port class ref 0 or 1 0r 2 or 3
        
"""


def create_outputdir(outputdir,device_label):

    dirpath=outputdir+device_label
    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)

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

    return L3_ip_dst_set,L3_ip_dst_counter


def parse_pcap(outputdir,capture,device_label,id_pcap):
    

    #Open the given passed pcap/capture to feed the buffer
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
        pck_rawdata = 0

        
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

                if tcp.sport == 80 or tcp.dport == 80:
                    L7_http = 1               
                if tcp.sport == 443 or tcp.dport == 443:
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

        #Dataframe to be pushed into csvpck_size
        ar2={'ARP':[L2_arp],'LLC':[L2_llc],'EAPOL':[L3_eapol],'Pck_size':[pck_size],'Pck_rawdata':[pck_rawdata],'IP_padding':[ip_padding],'IP_ralert':[ip_ralert],'IP_add_count':[L3_ip_dst_counter],'Portcl_src':[port_class_src],'Portcl_dst':[port_class_dst],'ICMP':[L3_icmp],'ICMP6':[L3_icmp6],'TCP':[L4_tcp],'UDP':[L4_udp],'HTTPS':[L7_https],'HTTP':[L7_http],'DHCP':[L7_dhcp],'BOOTP':[L7_bootp],'SSDP':[L7_ssdp],'DNS':[L7_dns],'MDNS':[L7_mdns],'NTP':[L7_ntp],'Label': [device_label]}
        headers_name=['ARP','LLC','EAPOL','Pck_size','Pck_rawdata','IP_padding','IP_ralert','IP_add_count','Portcl_src','Portcl_dst','ICMP','ICMP6','TCP','UDP','HTTPS','HTTP','DHCP','BOOTP','SSDP','DNS','MDNS','NTP','Label'] 
        df2= pandas.DataFrame(data=ar2,columns=headers_name)

        #Create dir for CSVs
        create_outputdir(outputdir,device_label)

        #Create CSV
        csv_file=outputdir+device_label+'/file_'+device_label+'_'+str(id_pcap)+'.csv'
    
        df2.to_csv(csv_file, sep='\t', encoding='utf-8',mode='a', header=False)

        #Display features per packet
        print (ar2)
        print ('\n')
    
    f.close()


def main(argv):


    version='IoT_Sentinel parse_pcap v1.0'
    inputpcap = ''
    inputdir = ''
    outputdir = ''

    #Variable for get_dest_ip_counter function

    global L3_ip_dst_counter 
    global L3_ip_dst_set 
    L3_ip_dst_set = []

    #Global Options (getopt)

    try:
        opts, args = getopt.getopt(argv,"hd:o:i:l:",["idir=","odir=","ifile=","label="])
    except getopt.GetoptError:
        print version+'\nusage:\tparse_pcap.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print version+'\nusage:\tparse_pcap.py -d <inputdir> [or] -i <inputpcap> -l <label> [and] -o <outputdir>'
            sys.exit()
        elif opt in ("-d", "--dir"):
            op = 1
            inputdir = arg
            device_label=os.listdir(inputdir)
        elif opt in ("-o", "--odir"):
            outputdir = arg
        elif opt in ("-i", "--ifile"):
            op = 2
            inputpcap= arg
            id_pcap = 1
            L3_ip_dst_counter=1
        elif opt in ("-l", "--device_label"):
            device_label = [arg]



    print 'IoT_Sentinel: parse_pcap.py v1.0\n'
    i = 0
    id_pcap=0
    while i < len(device_label):
        if op == 1:    
            filename_path=inputdir+device_label[i]+'/*.pcap'
            print '\nINPUTDIR: ',inputdir
            print '\nOUTPUTDIR: ',outputdir
            print '\nDEVICE TESTED:\n'+str(device_label)+'\n\n'
        elif op == 2:
            filename_path=inputpcap
            print '\nINPUTPCAP: ',inputdir
            print '\nOUTPUTDIR: ',outputdir
            print '\nDEVICE TESTED:\n'+str(device_label)

        print '\nSTARTING...\n' 

        for filename in glob.glob(filename_path):
            if os.path.isfile(filename):
                del L3_ip_dst_set[:]
                L3_ip_dst_counter = 1 
                print('Device: '+device_label[i]+'\n\n')
                parse_pcap(outputdir,filename,device_label[i],id_pcap)
                id_pcap += 1
            else:
                print('file does not exist')
        i += 1


if __name__== "__main__":
  main(sys.argv[1:])