from scapy.all import *

def print_pkt(pkt):
        pkt.show()

iface=input("interface id:")
print("sniffing.....")
pkt = sniff(iface=str(iface), 
                filter='src host 128.230', 
                prn=print_pkt)

