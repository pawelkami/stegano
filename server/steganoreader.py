#!/usr/bin/python
from scapy.all import *

stars = lambda n: "*" * n


def read(packet):
    tcp_packet = packet.getlayer(TCP)
    print('Read secret message: ' + chr(tcp_packet.urgptr))


def GET_print(packet):
    return "\n".join((
        stars(40) + "GET PACKET" + stars(40),
        "\n".join(packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")),
        stars(90)))


sniff(prn=read,
    filter="tcp port 80")
