from scapy.all import *

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng",  "multiplescans.pcapng",  "scan.pcapng",  "tcp_syn_scan.pcapng"]

destinationPorts = {}
sourcePorts = {}

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(basePath + paths[0])
print("Loading Packets")
print()
# Let's iterate through every packet
for packet in packets:
    # print("$$$$$*****PACKET-BEGIN*****$$$$$")
    try:
        IP = packet['IP']
        # print("\t--sIP--")
        # print("IP Src:   " + str(IP.src))
        # print("IP Dst:   " + str(IP.dst))
        # print("Flags:   " + str(IP.flags))
        TCP = packet['TCP']
        # print("\t--TCP--")
        # print("TCP Src: " + str(TCP.sport))
        # print("TCP Dst: " + str(TCP.dport))
        # print("Options: " + str(TCP.options))
        # print("Flags:   " + str(TCP.flags))
        # print("Window:  " + str(TCP.window))
        timeStamp = ()
        if len(TCP.options) != 0:
            for x in TCP.options:
                if(x.__contains__('Timestamp')):
                    timeStamp = x[1]
                    print(timeStamp)

        # check if address is local
        if IP.dst == "129.119.201.21":
            if TCP.sport in sourcePorts:
                continue
            else:
                x = {
                    "start": timeStamp[0],
                    "end": timeStamp[1],
                    "dst": {
                        TCP.dst : 1
                    },
                }
                sourcePorts[TCP.sport] = x
    except IndexError:
        packet.show()
        continue
    # print("$$$$$*****PACKET-END*****$$$$$")
    print("")
print(destinationPorts)
print(sourcePorts)
    # print(TCP.sport)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])