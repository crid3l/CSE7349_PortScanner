from scapy.all import *
import datetime
from itertools import groupby
from operator import itemgetter
import sys

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng", "scan.pcapng",  "tcp_syn_scan.pcapng"]

destinationPorts = {}
sourcePorts = {}

ip = "129.119.201.21"

if len(sys.argv) == 2:
    ip = sys.argv[1]

# rdpcap comes from scapy and loads in our pcap file
print("Loading Packets")
packets = rdpcap(basePath + paths[1])
print("")
# Let's iterate through every packet
for packet in packets:
    # print("$$$$$*****PACKET-BEGIN*****$$$$$")
    packet.show()
    try:
        IP = {}
        if 'IP' in packet:
            IP = packet['IP']
        # print("\t--sIP--")
        # print("IP Src:   " + str(IP.src))
        # print("IP Dst:   " + str(IP.dst))
        # print("Flags:   " + str(IP.flags))
        flag = False
        TCP = {}
        if 'TCP' in packet:
            TCP = packet['TCP']
            flag = True
        # elif 'UDP' in packet:
        #     TCP = packet['UDP']
        else:
            continue

        # print("\t--TCP--")
        # print("TCP Src: " + str(IP.src))
        # print("TCP Dst: " + str(TCP.dport))
        # print("Options: " + str(TCP.options))
        # print("Flags:   " + str(TCP.flags))
        # print("Window:  " + str(TCP.window))
                        # print(timeStamp)

        # check if address is local
        if IP.dst == ip:
            # check if current packet TCP field exist in sourceport list
            if IP.src in sourcePorts:
                port = sourcePorts[IP.src]
                # if so, we wan to update the end field
                
                if 'end' not in port or port['end'] < packet.time:
                    port['end'] = packet.time
                #and add or increment a new destination.
                if TCP.dport in port['dst']:
                    port['dst'][TCP.dport] = port['dst'][TCP.dport] + 1
                else:
                    port['dst'][TCP.dport] = 1
                sourcePorts[IP.src] = port
            # or initialize a new  port in the list
            else:
                x = {
                    "start": packet.time,
                    "dst": {
                        TCP.dport : 1
                    }
                }
                sourcePorts[IP.src] = x
        else:
            continue
    except IndentationError as e:
        print(e)
        packet.show()
        continue
    # print("$$$$$*****PACKET-END*****$$$$$")
for key, val in sourcePorts.items():
    portList = []
    i = 0
    for dst, cnt in val['dst'].items():
        if cnt <= 3:
            i = i + 1
            portList.append(dst)
        if i >= 10:
            break
    if i >= 10:
        portRange = val['dst'].keys()
        portRange.sort()
        print("IP " + key + " likely engaged in Port Scanning")
        time = datetime.datetime.fromtimestamp(val['start']).strftime('%c') + " to " + datetime.datetime.fromtimestamp(val['end']).strftime('%c')
        print(time)
        print("Ports: ")
        print(portList)
        # print(portRange)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])