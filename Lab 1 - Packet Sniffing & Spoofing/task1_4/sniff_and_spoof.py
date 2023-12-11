from scapy.all import *

def spoof_pkt(pkt):
  if (pkt[ICMP].type == ICMP(type="echo-request").type):
    spoofed = IP(src=pkt[IP].dst, dst=pkt[IP].src)/ICMP(
                type="echo-reply", id=pkt[ICMP].id,
                seq=pkt[ICMP].seq)/ pkt[Raw].load
    send(spoofed)

def sniff_pkt():
  print("sniffing.....")
  interfaces = ['lo', 'enp0s3']
  pkt = sniff(iface=interfaces,
                filter='icmp',
                prn=spoof_pkt)

sniff_pkt()

