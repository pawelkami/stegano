#!/bin/python3
#-*- coding: utf-8 -*-

from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket


def read_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return data		


textToHide = read_file("/stegano/Antygona.txt")
byte_num = 0


def modify(packet):
    global server_address
    scapy_pkt = Ether() / IP(dst=server_address) / TCP(dport=80) / packet.get_payload()
    tcp_pkt = scapy_pkt.getlayer(TCP)
    global textToHide
    global byte_num

    if byte_num < len(textToHide):
        tcp_pkt.flags &= 0xef       # mask which disabled urgent pointer
        tcp_pkt.urgptr = (textToHide[byte_num] << 8) | (textToHide[byte_num + 1])
        byte_num += 2

    print('Secret message: ' + chr(tcp_pkt.urgptr))
    sendp(scapy_pkt)
    packet.drop()


nfqueue = NetfilterQueue()
nfqueue.bind(0, modify)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
server_address = socket.gethostbyname('server')

try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('')

s.close()
nfqueue.unbind()
