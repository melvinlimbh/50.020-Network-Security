from scapy.all import *
a = IP() # IP of host / attacker
a.dst = '10.9.0.6'
a.show()
b = ICMP()
p = a/b
p.src = '1.2.3.4'
p.dst = '10.9.0.5'
print(f"change source to {p.src}\nchange destination to {p.dst}")
send(p)

