#!/usr/bin/env python3

import fcntl
import struct
import os
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Lim%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Configure to get interface up
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

while True:
# Get a packet from the tun interface
   print("READING PKT.....")
   packet = os.read(tun, 2048)
   if packet:
      ip = IP(packet)
      #ip.show()
      print(ip.summary())
      summary = ip.summary().split(" ")
      # look for ICMP request packets
      if ("ICMP" in summary and "echo-request" in summary):
         print("constructing ICMP reply...")
         newicmp = ICMP( type=0, id = ip[ICMP].id, seq=ip[ICMP].seq)
         newip = IP(src= ip.dst, dst=ip.src)

         if ip[Raw]:
            data = ip[Raw].load
            newpkt = newip/newicmp/data
         else:
            newpkt = newip/newicmp
         #newpkt.show()
         data = b'HELLO from Lim0'
         #os.write(tun, bytes(newpkt))
         os.write(tun, bytes(data))

