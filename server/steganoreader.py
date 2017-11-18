#!/usr/bin/python3
# -*- coding: utf-8 -*-

from scapy.all import *
import socket
from enum import Enum

secret_messages = {}
server_address = socket.gethostbyname('server')


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


def decrypt(message, key):
    return xor(message, key)


def get_encryption_key(scapy_packet):
    ip_pkt = scapy_packet.getlayer(IP)
    return bytes([ip_pkt.id & 0xff])


def find_custom_option(options):
    for option in options:
        if option[0] in \
                (MessageType.Short.value, MessageType.First.value, MessageType.Last.value, MessageType.Middle.value):
            return option
    return None


def get_message_length(scapy_packet):
    tcp_pkt = scapy_packet.getlayer(TCP)
    return tcp_pkt.reserved | ((scapy_packet.getlayer(IP).flags & 0x4) << 1)


def get_hidden_message(scapy_packet):
    tcp_pkt = scapy_packet.getlayer(TCP)
    message = bytes()

    msg_len = get_message_length(scapy_packet)

    if msg_len > 0:
        message += bytes([tcp_pkt.window >> 8])
    if msg_len > 1:
        message += bytes([tcp_pkt.window & 0xff])
    if msg_len > 2:
        message += find_custom_option(tcp_pkt.options)[1]
    message = decrypt(message, get_encryption_key(scapy_packet))

    return message


def is_hidden_message(scapy_packet):
    return get_message_length(scapy_packet) > 0


def get_message_type(packet):
    options = packet.getlayer(TCP).options
    if options is None or len(options) == 0:
        return MessageType.Middle

    custom_option = find_custom_option(options)
    if custom_option is not None:
        return MessageType(custom_option[0])
    return MessageType.Middle


def write_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)


def read(packet):
    global secret_messages
    global server_address

    if packet.getlayer(IP).src == server_address:
        return

    if not is_hidden_message(packet):
        print("No steganography in message from: " + packet[IP].src)
        return

    if not packet.getlayer(IP).src in secret_messages:
        secret_messages[packet.getlayer(IP).src] = bytes()

    hidden_message = get_hidden_message(packet)
    secret_messages[packet.getlayer(IP).src] += hidden_message
    print("Secret message detected from: " + packet.getlayer(IP).src)
    print(str(hidden_message, encoding='cp1250'))

    message_type = get_message_type(packet)

    if message_type == MessageType.First:
        print('First packet')
    elif message_type == MessageType.Last:
        print('Last packet')
        write_file(packet[IP].src, secret_messages[packet[IP].src])

    elif message_type == MessageType.Middle:
        print('Middle packet')
    elif message_type == MessageType.Short:
        print('Short packet')
        write_file(packet[IP].src, secret_messages[packet[IP].src])


sniff(prn=read,
      filter="tcp port 80")
