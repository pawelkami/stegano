#!/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import logging

# first changing then importing scapy because it takes big amount of time
if len(sys.argv) != 2:
    print("Usage: detector.exe <pcap file>")
    sys.exit(1)

if not os.path.exists(sys.argv[1]):
    print("File " + sys.argv[1] + " doesn't exist")
    sys.exit(1)

print("Work in progress...")
# disabling scapy warnings (it was always showing warning message during import)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def is_hidden_message(packet):
    if not packet.haslayer(TCP):
        return False
    tcp = packet.getlayer(TCP)
    return (tcp.reserved | ((packet.getlayer(IP).flags & 0x4) << 1)) > 0


def parse_pcap(filename):
    pcap = rdpcap(filename)
    for pkt in pcap:
        if is_hidden_message(pkt):
            print("File contains hidden data!!!")
            return

    print("File does NOT contain hidden data")


parse_pcap(sys.argv[1])
