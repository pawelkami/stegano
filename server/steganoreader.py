#!/usr/bin/python3
from scapy.all import *

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

    message += bytes([tcp_pkt.urgptr >> 8])
    message += bytes([tcp_pkt.urgptr & 0xff])
    message = decrypt(message, getEncryptKey(scapy_packet))

    return message

secret_messages = {}

def read(packet):
    global secret_messages
    if not packet[IP].src in secret_messages:
        secret_messages[packet[IP].src] = bytes()

    tcp_packet = packet.getlayer(TCP)

    secret_messages[packet[IP].src] += getHiddenMessage(packet) #bytes([tcp_packet.urgptr >> 8, tcp_packet.urgptr & 0xff])
    print(secret_messages[packet[IP].src])

def GET_print(packet):
    return "\n".join((
        stars(40) + "GET PACKET" + stars(40),
        "\n".join(packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")),
        stars(90)))


sniff(prn=read,
    filter="tcp port 80")
