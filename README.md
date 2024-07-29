Network Packet Analyzer
Overview

This project is a network packet analyzer implemented in Python using the Scapy library. It captures and analyzes Ethernet, IP, TCP, and UDP headers from network packets. This tool is useful for network diagnostics, monitoring, and understanding the structure of network protocols.
Author

    Name: Daniel Ishaku Ando
    Website: danishkute.carrd.co

Prerequisites

    Python 3
    Scapy library

Installation

    Clone the Repository:

    bash

git clone <repository-url>
cd <repository-directory>

Install Scapy:

bash

    pip install scapy

Usage

To run the network packet analyzer, execute the script:

bash

sudo python3 network_packet_analyzer.py

(Note: Running this script may require root privileges to capture network packets.)
Code Description
1. Imports and Author Information

The script begins with the necessary imports and author information:

python

#!/usr/bin/python3

from scapy.all import *

2. Analyzing UDP Headers

The analyze_udp_header function extracts and prints key UDP header fields, such as source port, destination port, length, and checksum:

python

def analyze_udp_header(packet):
    udp_hdr = packet[UDP]
    src_port = udp_hdr.sport
    dst_port = udp_hdr.dport
    length = udp_hdr.len
    checksum = udp_hdr.chksum

    print("_______________UDP HEADER_________________")
    print("Source: %hu" % src_port)
    print("Destination: %hu" % dst_port)
    print("Length: %hu" % length)
    print("Checksum: %hu" % checksum)

3. Analyzing TCP Headers

The analyze_tcp_header function extracts and prints key TCP header fields, such as source port, destination port, sequence number, acknowledgment number, flags, and checksum. It also decodes the TCP flags:

python

def analyze_tcp_header(packet):
    tcp_hdr = packet[TTCP]
    src_port = tcp_hdr.sport
    dst_port = tcp_hdr.dport
    seq_num = tcp_hdr.seq
    ack_num = tcp_hdr.ack
    data_offset = tcp_hdr.dataofs
    reserved = tcp_hdr.reserved
    flags = tcp_hdr.flags
    window = tcp_hdr.window
    checksum = tcp_hdr.chksum
    urg_prt = tcp_hdr.urgptr

    urg = bool(flags & 0x20)
    ack = bool(flags & 0x10)
    psh = bool(flags & 0x08)
    rst = bool(flags & 0x04)
    syn = bool(flags & 0x02)
    fin = bool(flags & 0x01)

    print("_____________TCP HEADER_________________")
    print("Source: %hu" % src_port)
    print("Destination: %hu" % dst_port)
    print("Seq: %hu" % seq_num)
    print("Ack: %hu" % ack_num)
    print("Flags:")
    print("URG: %hu" % urg)
    print("ACK: %hu" % ack)
    print("PSH: %hu" % psh)
    print("RST: %hu" % rst)
    print("SYN: %hu" % syn)
    print("FIN: %hu" % fin)
    print("Window: %hu" % window)
    print("Checksum: %hu" % checksum)

4. Analyzing IP Headers

The analyze_ip_header function extracts and prints key IP header fields, such as version, IHL, TOS, total length, ID, flags, TTL, protocol, checksum, and IP addresses. It determines the protocol (TCP or UDP) based on the protocol number:

python

def analyze_ip_header(packet):
    ip_hdr = packet[IP]
    ver = ip_hdr.version
    ihl = ip_hdr.ihl
    tos = ip_hdr.tos
    tot_length = ip_hdr.len
    ip_id = ip_hdr.id
    flags = ip_hdr.flags
    frags_offset = ip_hdr.frag
    ip_ttl = ip_hdr.ttl
    ip_proto = ip_hdr.proto
    checksum = ip_hdr.chksum
    src_address = ip_hdr.src
    dst_address = ip_hdr.dst

    print("________________________IP HEADER______________________")
    print("Version: %hu" % ver)
    print("IHL: %hu" % ihl)
    print("TOS: %hu" % tos)
    print("Length: %hu" % tot_length)
    print("ID: %hu" % ip_id)
    print("Offset: %hu" % frags_offset)
    print("TTL: %hu" % ip_ttl)
    print("Proto: %hu" % ip_proto)
    print("Checksum: %hu" % checksum)
    print("Source IP: %s" % src_address)
    print("Destination IP: %s" % dst_address)

    if ip_proto == 6:
        return "TCP"
    elif ip_proto == 17:
        return "UDP"
    else:
        return "OTHER"

5. Analyzing Ethernet Headers

The analyze_ether_header function extracts and prints key Ethernet header fields, such as destination MAC address, source MAC address, and protocol type. It checks if the protocol is IPv4 (0x0800):

python

def analyze_ether_header(packet):
    eth_hdr = packet[Ether]
    dest_mac = eth_hdr.dst
    src_mac = eth_hdr.src
    proto = eth_hdr.type

    print("______________ETHERNET HEADER_______________")
    print("Destination MAC: %s" % dest_mac)
    print("Source MAC: %s" % src_mac)
    print("PROTOCOL: %hu" % proto)

    if proto == 0x0800:
        return True
    return False

6. Packet Handler

The packet_handler function handles captured packets, checks for the presence of Ethernet and IP layers, and calls the appropriate analysis functions for TCP or UDP headers:

python

def packet_handler(packet):
    if packet.haslayer(Ether):
        if analyze_ether_header(packet):
            if packet.haslayer(IP):
                protocol = analyze_ip_header(packet)
                if protocol == "TCP":
                    if packet.haslayer(TCP):
                        analyze_tcp_header(packet)
                elif protocol == "UDP":
                    if packet.haslayer(UDP):
                        analyze_udp_header(packet)

7. Main Function

The main function uses the sniff function from Scapy to capture packets and pass them to the packet_handler function for analysis:

python

if __name__ == "__main__":
    sniff(prn=packet_handler)

License

This project is licensed under the MIT License - see the LICENSE file for details.
