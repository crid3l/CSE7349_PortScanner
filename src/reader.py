from scapy.all import *

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(basePath + paths[0])
print("Loading Packets")
print()
# Let's iterate through every packet
for packet in packets:
    print("-----PACKET-BEGIN-----")
    packet.show()
    # try:
    #     TCP = packet['TCP']
    #     print("TCP Src: " + str(TCP.sport))
    #     print("TCP Dst: " + str(TCP.dport))
    #     print("Options: " + str(TCP.options))
    #     if len(TCP.options) != 0:
    #         for x in TCP.options:
    #             if(x.__contains__('Timestamp')):
    #                 timeStamp = x[1]
    #                 print(timeStamp)
    # except IndexError:
    #     packet.show()
    #     continue
    print("-----PACKET-END-----")
    print()
    # print(TCP.sport)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])