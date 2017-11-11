#!/bin/python3
#-*- coding: utf-8 -*-

from scapy.all import *
import sys

def isHiddenMessage(packet):
    if not packet.haslayer(TCP):
        return False
    tcp = packet[TCP]
    return (tcp.reserved | ((packet.getlayer(IP).flags & 0x4) << 1)) > 0


def parsePcap(filename):
    pcap = rdpcap(filename)
    for pkt in pcap:
        if isHiddenMessage(pkt):
            print("File contains hidden data!!!")
            return

    print("File does NOT contain hidden data")



parsePcap(sys.argv[1])