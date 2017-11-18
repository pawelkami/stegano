#!/bin/python3
# -*- coding: utf-8 -*-

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


def get_encryption_key(scapy_packet):
    ip_pkt = scapy_packet.getlayer(IP)
    return bytes([ip_pkt.id & 0xff])


def prepare_message(scapy_packet):
    global text_to_hide
    global byte_num
    tcp_pkt = scapy_packet.getlayer(TCP)

    msg_len = MESSAGE_MAX_LENGTH if len(text_to_hide) - byte_num >= MESSAGE_MAX_LENGTH else len(text_to_hide) - byte_num

    msg_len = random.randint(1, msg_len)  # random number for tests and for complication of analyse ;)

    if byte_num == 0:
        if msg_len == len(text_to_hide):
            message_type = MessageType.Short
        else:
            message_type = MessageType.First
    elif byte_num + msg_len == len(text_to_hide):
        message_type = MessageType.Last
    else:
        message_type = MessageType.Middle

    tcp_pkt.reserved |= msg_len & 0x7

    scapy_packet.getlayer(IP).flags |= (msg_len & 0x08) >> 1

    message = bytes()
    for i in range(msg_len):
        message += bytes([text_to_hide[byte_num]])
        byte_num += 1

    print("Plain message: " + message.decode("windows-1250"))
    message = encrypt(message, get_encryption_key(scapy_packet))

    if msg_len > 0:
        tcp_pkt.window = message[0] << 8
    if msg_len > 1:
        tcp_pkt.window |= message[1]
    if msg_len > 2 or message_type in (MessageType.Short, MessageType.First, MessageType.Last):
        # add custom TCP option
        if tcp_pkt.dataofs > 5:
            tcp_pkt.options.append((message_type.value, message[2:]))
        else:
            tcp_pkt.options = [(message_type.value, message[2:])]

        # if custom option length is not a multiplicity of 4, apply padding
        padding = 0 if (2 + len(message[2:])) % 4 == 0 else 4 - (2 + len(message[2:])) % 4

        for _ in range(0, padding):
            tcp_pkt.options.append(("NOP", None))

        # data offset is the number of 4 byte words between TCP header start and end
        tcp_pkt.dataofs += int((2 + len(message[2:]) + padding) / 4)
        scapy_packet.getlayer(IP).len += (2 + len(message[2:]) + padding)

    del scapy_packet.getlayer(IP).chksum
    del scapy_packet.getlayer(TCP).chksum

    return scapy_packet


def read_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return data


def modify(packet):
    global text_to_hide
    global byte_num

    if byte_num < len(text_to_hide):
        scapy_pkt = IP(packet.get_payload())
        scapy_pkt = prepare_message(scapy_pkt)
        packet.set_payload(bytes(scapy_pkt))

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, modify)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

text_to_hide = read_file("/stegano/Antygona.txt")
byte_num = 0

try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('')

s.close()
nfqueue.unbind()
