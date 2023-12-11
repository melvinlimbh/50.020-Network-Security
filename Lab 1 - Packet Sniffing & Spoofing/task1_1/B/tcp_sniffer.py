from scapy.all import *

def print_pkt(pkt):
        pkt.show()

iface=input("interface id:")
print("sniffing.....")
pkt = sniff(iface=str(iface),
                filter='tcp and port 23 and src host 10.9.0.6', 
                prn=print_pkt)

