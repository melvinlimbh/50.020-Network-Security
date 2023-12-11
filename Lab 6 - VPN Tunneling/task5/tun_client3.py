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

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Configure to get interface up
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# route needs to be added everytime the tunnel script is run
os.system("ip route add 192.168.60.0/24 dev Lim0")

ip = "10.9.0.11" # VPN IP
port = 9090
while True:
# this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock: # if file descriptor is socket
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            # send to tunnel
            os.write(tun, bytes(pkt))

  
        if fd is tun: # if file descriptor is tunnel
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            # send to UDP socket from host U
            sock.sendto(packet, (ip, port))