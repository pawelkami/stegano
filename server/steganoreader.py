#!/usr/bin/python3
from scapy.all import *

stars = lambda n: "*" * n

secret_messages = {}

def read(packet):
    global secret_messages
    if not packet[IP].src in secret_messages:
        secret_messages[packet[IP].src] = bytes()

    tcp_packet = packet.getlayer(TCP)

    secret_messages[packet[IP].src] += bytes([tcp_packet.urgptr >> 8, tcp_packet.urgptr & 0xff])
    print(secret_messages[packet[IP].src])

def GET_print(packet):
    return "\n".join((
        stars(40) + "GET PACKET" + stars(40),
        "\n".join(packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")),
        stars(90)))


sniff(prn=read,
    filter="tcp port 80")
