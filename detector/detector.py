#!/bin/python3
#-*- coding: utf-8 -*-

from scapy.all import *
import sys

def isHiddenMessage(packet):
    if not packet.haslayer(TCP):
        return False

    tcp = packet[TCP]
    if tcp.urgptr != 0 and not (tcp.flags & 0x20):
        return True
    return False


def parsePcap(filename):
    pcap = rdpcap(filename)
    for pkt in pcap:
        if isHiddenMessage(pkt):
            print("File contains hidden data!!!")
            return

    print("File does NOT contain hidden data")



parsePcap(sys.argv[1])