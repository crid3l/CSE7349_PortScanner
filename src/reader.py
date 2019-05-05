from scapy.all import *

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(basePath + paths[0])
print("Loading Packets")
# Let's iterate through every packet
for packet in packets:
    TCP = packet['TCP']
    print("TCP Src" + str(TCP.sport))
    print("TCP Dst" + str(TCP.dport))
    print("Options" + str(TCP.options))

    # try:
    #     TCP = packet['TCP']
    #     print(TCP.options)
    # except IndexError:
    #     TCP.show()
    #     pass

    # print(TCP.sport)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])