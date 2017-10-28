#!/bin/python
#-*- coding: utf-8 -*-

from netfilterqueue import NetfilterQueue
import socket

def readFile(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return data		

def print_and_accept(pkt):
    print(pkt)
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

textToHide = readFile("/stegano/Antygona.txt")

try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('')

s.close()
nfqueue.unbind()
