#!/usr/bin/env python

from scapy.all import *

packet_ip = IP(dst="192.168.1.143" , src="192.168.1.222")

udp_1 = UDP(dport=123, sport=123)
payload_1 = "pidfile"

udp_2 = UDP(dport=53, sport=4443)
payload_2 = "\xbe\xba\xfe\xca"

udp_3 = UDP(dport=16464, sport=4444)
payload_3 = "\x28\x28\x28\x28\x28\x94\x8d\xab\x28\x28\x28\x28\x28\x28\x28\x28"

packet_1 = packet_ip/udp_1/payload_1
packet_2 = packet_ip/udp_2/payload_2
packet_3 = packet_ip/udp_3/payload_3

packets= [packet_1, packet_2, packet_3]

send(packets, loop=1)