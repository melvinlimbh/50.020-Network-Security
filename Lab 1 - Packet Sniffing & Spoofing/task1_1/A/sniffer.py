from scapy.all import *

def print_pkt(pkt):
	pkt.show()

iface=input("interface id:")
print("sniffing.....")
pkt = sniff(iface=str(iface), 
		filter='icmp', 
		prn=print_pkt)

