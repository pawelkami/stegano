#!/usr/bin/python3
from scapy.all import *
import socket

stars = lambda n: "*" * n

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

def getHiddenMessage(scapy_packet):
    tcp_pkt = scapy_packet.getlayer(TCP)
    message = bytes()

    msgLen = tcp_pkt.reserved | ((scapy_packet.getlayer(IP).flags & 0x4) << 1)

    if msgLen > 0:
        message += bytes([tcp_pkt.urgptr >> 8])
    if msgLen > 1:
        message += bytes([tcp_pkt.urgptr & 0xff])
    if msgLen > 2:
        message += bytes([tcp_pkt.window >> 8])
    if msgLen > 3:
        message += bytes([tcp_pkt.window & 0xff])
    if msgLen > 4:
        message += tcp_pkt.options[-1][1]

    message = decrypt(message, getEncryptKey(scapy_packet))

    return message

def isHiddenMessage(scapy_packet):
    pkt = scapy_packet.getlayer(TCP)
    if pkt.urgptr != 0 and not (pkt.flags & 0x20):
        return True
    return False

secret_messages = {}

def read(packet):
    global secret_messages
    global server_address

    if packet[IP].src == server_address:
        return

    if not isHiddenMessage(packet):
        print("No steganography in message from: " + packet[IP].src)
        return

    print("Secret message detected from: " + packet[IP].src)

    if not packet[IP].src in secret_messages:
        secret_messages[packet[IP].src] = bytes()

    secret_messages[packet[IP].src] += getHiddenMessage(packet)
    print(secret_messages[packet[IP].src])

def GET_print(packet):
    return "\n".join((
        stars(40) + "GET PACKET" + stars(40),
        "\n".join(packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")),
        stars(90)))

server_address = socket.gethostbyname('server')

sniff(prn=read,
    filter="tcp port 80")
