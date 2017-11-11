#!/bin/python3
#-*- coding: utf-8 -*-

from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket
import random
from enum import Enum

MESSAGE_MAX_LENGTH = 12


class MessageType(Enum):
    Short = 0xfa
    First = 0xfb
    Middle = 0xfc
    Last = 0xfd


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

    msgLen = MESSAGE_MAX_LENGTH if len(textToHide) - byte_num >= MESSAGE_MAX_LENGTH else len(textToHide) - byte_num

    msgLen = random.randint(1, msgLen)  # random number for tests and for complication of analyse ;)

    if byte_num == 0:
        if msgLen == len(textToHide):
            message_type = MessageType.Short
        else:
            message_type = MessageType.First
    elif byte_num + msgLen == len(textToHide):
        message_type = MessageType.Last
    else:
        message_type = MessageType.Middle

    tcp_pkt.reserved |= msgLen & 0x7

    scapy_packet[IP].flags |= (msgLen & 0x08) >> 1

    message = bytes()
    for i in range(msgLen):
        message += bytes([textToHide[byte_num]])
        byte_num += 1

    print("Plain message: " + message.decode("windows-1250"))
    message = encrypt(message, getEncryptKey(scapy_packet))

    if msgLen > 0:
        tcp_pkt.window = message[0] << 8
    if msgLen > 1:
        tcp_pkt.window |= message[1]
    if msgLen > 2 or message_type in (MessageType.Short, MessageType.First, MessageType.Last):
        # add custom TCP option
        if (tcp_pkt.dataofs > 5):
            tcp_pkt.options.append((message_type.value, message[2:]))
        else:
            tcp_pkt.options = [(message_type.value, message[2:])]

        # if custom option length is not a multiplicity of 4, apply padding
        padding = 0 if (2 + len(message[2:])) % 4 == 0 else 4 - (2 + len(message[2:])) % 4

        for _ in range(0, padding):
            tcp_pkt.options.append(('NOP', None))

        # data offset is the number of 4 byte words between TCP header start and end
        tcp_pkt.dataofs += int((2 + len(message[2:]) + padding) / 4)
        scapy_packet.getlayer(IP).len += (2 + len(message[2:]) + padding)

    del scapy_packet[IP].chksum
    del scapy_packet[TCP].chksum

    return scapy_packet


def read_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return data

def modify(packet):
    global server_address
    scapy_pkt = IP(packet.get_payload())
    global textToHide
    global byte_num

    if byte_num < len(textToHide):
        scapy_pkt = prepareMessage(scapy_pkt)

    packet.set_payload(bytes(scapy_pkt))
    packet.accept()

textToHide = read_file("/stegano/Antygona.txt")
byte_num = 0

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
