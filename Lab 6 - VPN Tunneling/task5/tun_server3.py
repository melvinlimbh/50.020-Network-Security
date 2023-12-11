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
os.system(f"ip addr add 192.168.53.11/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

ip = "10.9.0.5"
while True:
# this will block until at least one interface is ready
  ready, _, _ = select.select([sock, tun], [], [])

  for fd in ready:
    if fd is sock: # if file descriptor is socket, receive from socket
      data, (ip, PORT) = sock.recvfrom(2048)
      pkt = IP(data)
      print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
      # send to tunnel
      os.write(tun, bytes(pkt))


    if fd is tun: # if file descriptor is tunnel, read from tunnel
      packet = os.read(tun, 2048)
      pkt = IP(packet)
      print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
      # send to UDP socket from VPN server to host U
      sock.sendto(packet, (ip, PORT))