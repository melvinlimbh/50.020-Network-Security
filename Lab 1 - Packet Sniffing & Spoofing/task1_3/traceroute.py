from scapy.all import *

a = IP()
a.dst='74.125.200.100' #google.com
for ttl in range(1,40):
    a.ttl = ttl
    b=ICMP()
    p = a/b
    p.show()
    send(p)
