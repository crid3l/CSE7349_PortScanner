from scapy.all import *

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

# rdpcap comes from scapy and loads in our pcap file
print("Loading Packets")
packets = rdpcap(basePath + paths[0])

# Let's iterate through every packet
for packet in packets:
    print(packet)