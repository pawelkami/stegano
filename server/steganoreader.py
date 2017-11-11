#!/usr/bin/python3
from scapy.all import *
import socket
from enum import Enum


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

def getEncryptKey(scapy_packet):
    pkt = scapy_packet.getlayer(IP)
    return bytes([pkt.id & 0xff])

def findCustomOption(options):
    for option in options:
        if option[0] in (MessageType.Short.value, MessageType.First.value, MessageType.Last.value, MessageType.Middle.value):
            return option
    return None

def getMessageLength(scapy_packet):
    tcp_pkt = scapy_packet.getlayer(TCP)
    return tcp_pkt.reserved | ((scapy_packet.getlayer(IP).flags & 0x4) << 1)

def getHiddenMessage(scapy_packet):
    tcp_pkt = scapy_packet.getlayer(TCP)
    message = bytes()

    msgLen = getMessageLength(scapy_packet)

    if msgLen > 0:
        message += bytes([tcp_pkt.window >> 8])
    if msgLen > 1:
        message += bytes([tcp_pkt.window & 0xff])
    if msgLen > 2:
        message += findCustomOption(tcp_pkt.options)[1]
    message = decrypt(message, getEncryptKey(scapy_packet))

    return message

def isHiddenMessage(scapy_packet):
    return getMessageLength(scapy_packet) > 0

secret_messages = {}

def getMessageType(packet):
    options = packet[TCP].options
    if options is None or len(options) == 0:
        return MessageType.Middle

    custom_option = findCustomOption(options)
    if custom_option is not None:
        return MessageType(custom_option[0])
    return MessageType.Middle

def writeFile(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def read(packet):
    global secret_messages
    global server_address

    if packet[IP].src == server_address:
        return

    if not isHiddenMessage(packet):
        print("No steganography in message from: " + packet[IP].src)
        return

    if not packet[IP].src in secret_messages:
        secret_messages[packet[IP].src] = bytes()

    hidden_message = getHiddenMessage(packet)
    secret_messages[packet[IP].src] += hidden_message
    print("Secret message detected from: " + packet[IP].src)
    print(str(hidden_message, encoding='cp1250'))

    message_type = getMessageType(packet)

    if message_type == MessageType.First:
        print('First packet')
    elif message_type == MessageType.Last:
        print('Last packet')
        writeFile(packet[IP].src, secret_messages[packet[IP].src])

    elif message_type == MessageType.Middle:
        print('Middle packet')
    elif message_type == MessageType.Short:
        print('Short packet')
        writeFile(packet[IP].src, secret_messages[packet[IP].src])

server_address = socket.gethostbyname('server')

sniff(prn=read,
    filter="tcp port 80")
