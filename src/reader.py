from scapy.all import *
import datetime

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng", "scan.pcapng",  "tcp_syn_scan.pcapng"]

destinationPorts = {}
sourcePorts = {}

# rdpcap comes from scapy and loads in our pcap file
print("Loading Packets")
packets = rdpcap(basePath + paths[2])
print("")
# Let's iterate through every packet
for packet in packets:
    # print("$$$$$*****PACKET-BEGIN*****$$$$$")
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
        if IP.dst == "129.119.201.21":
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
    i = 0
    for dst, cnt in val['dst'].items():
        if cnt <= 3:
            i = i + 1
        if i >= 10:
            break
    if i >= 10:
        portRange = val['dst'].key().sort()
        
        print("IP " + key + " likely engaged in Port Scanning")
        str = datetime.datetime.fromtimestamp(val['start']).strftime('%c') + " to " + datetime.datetime.fromtimestamp(val['end']).strftime('%c')
        print(str)
        str = ""
        print("Port " + str(portRange[0]) + " ]------> " + "Port " + str( portRange[ len(portRange) ] ))
        print("")
    # print(IP.src)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])