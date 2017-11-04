#!/bin/python3
#-*- coding: utf-8 -*-

from netfilterqueue import NetfilterQueue
from scapy.all import *
from patches import TCPOptionsField_i2m_fixed
import socket


TCPOptionsField.i2m = TCPOptionsField_i2m_fixed

def xor(data, key):
    key = bytearray(key)
    data = bytearray(data)

    out = bytes()
    for i, d in enumerate(data):
        out += bytes([d ^ key[i % len(key)]])

    return out


def encrypt(message, key):
    return xor(message, key)

def getEncryptKey(scapy_packet):
    pkt = scapy_packet.getlayer(IP)
    return bytes([pkt.id & 0xff])

def prepareMessage(scapy_packet):
    global textToHide
    global byte_num
    tcp_pkt = scapy_packet.getlayer(TCP)

    message = bytes()
    for i in range(10):
        message += bytes([textToHide[byte_num]])
        byte_num += 1

    print("Plain message: " + message.decode("windows-1250"))
    message = encrypt(message, getEncryptKey(scapy_packet))

    tcp_pkt.flags &= 0xffdf
    tcp_pkt.urgptr = (message[0] << 8) | (message[1])
    tcp_pkt.window = (message[2] << 8) | (message[3])

    # add custom option of length 6 with hidden message
    tcp_pkt.options.append((0xfe, message[4:]))
    tcp_pkt.dataofs += 2

    scapy_packet.getlayer(IP).len += 8

    del scapy_packet[IP].chksum
    del scapy_packet[TCP].chksum

    return scapy_packet


def read_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return data


textToHide = read_file("/stegano/Antygona.txt")
byte_num = 0


def modify(packet):
    global server_address
    scapy_pkt = IP(packet.get_payload())
    global textToHide
    global byte_num

    if byte_num < len(textToHide):
        scapy_pkt = prepareMessage(scapy_pkt)

    packet.set_payload(bytes(scapy_pkt))
    packet.accept()


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
