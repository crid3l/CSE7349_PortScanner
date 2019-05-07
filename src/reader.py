from scapy.all import *

basePath = "./../../../../opt/scans/"
paths = ["connect_scan.pcapng", "scan.pcapng",  "tcp_syn_scan.pcapng"]

destinationPorts = {}
sourcePorts = {}

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
        if(flag):
            timeStamp = ()
            if len(TCP.options) != 0:
                for x in TCP.options:
                    if('Timestamp' in x):
                        try:
                            timeStamp = x[1]
                        except IndexError as e:
                            pass
                        # print(timeStamp)

        # check if address is local
        if IP.dst == "129.119.201.21":
            # check if current packet TCP field exist in sourceport list
            if IP.src in sourcePorts:
                # if so, we wan to update the end field
                port = sourcePorts[IP.src]
                try:
                    port['end'] = timeStamp[1]
                except: 
                    pass
                
                #and add or increment a new destination.
                if TCP.dport in port['dst']:
                    port['dst'][TCP.dport] = port['dst'][TCP.dport] + 1
                else:
                    port['dst'][TCP.dport] = 1
                sourcePorts[IP.src] = port
            # or initialize a new  port in the list
            else:
                try:
                    x = {
                        "start": timeStamp[0],
                        "end": timeStamp[1],
                        "dst": {
                            TCP.dport : 1
                        }
                    }
                except :
                    x = {
                        "start": -1,
                        "end": -1,
                        "dst": {
                            TCP.dport : 1
                        }
                    }
                sourcePorts[IP.src] = x
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
        print("IP " + key + " likely engaged in Port Scanning")
        print("Across" + str(val['start']) + " to " + str(val['end']))
        print("")
    # print(IP.src)
    # print(TCP.dport)
    # print(packet['TCP'].sport)
    # print(packet['TCP'])