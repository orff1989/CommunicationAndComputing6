#!/usr/bin/env python3
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


inter = ['enp0s3', 'lo']
pkt = sniff(iface=inter, filter='src host 10.0.2.15 and dst port 23', prn=print_pkt)
