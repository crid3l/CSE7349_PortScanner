#Network Security Port Scanner detector 
#Spring 2019
#Team: Muaz, Somto and Tyrone

from scapy.all import *
import datetime
from itertools import groupby
from operator import itemgetter
import sys


destinationPorts = {}
sourcePorts = {}

ip = "129.119.201.21"


if len(sys.argv) == 3:
    path = sys.argv[2]
    ip = sys.argv[1]

else:
    print("No file name provided")
    exit()

# rdpcap comes from scapy and loads in our pcap file
packets = path
print("Loading Packets")
print("")
# Let's iterate through every packet
for packet in packets:
    # print("$$$$$*****PACKET-BEGIN*****$$$$$")
    counter = 0
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
        elif 'UDP' in packet:
            TCP = packet['UDP']
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
                    },
                    "flags": TCP.flags
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
        print("")
        print("\033[93m {}\033[00m" .format("IP " + key + " likely engaged in Port Scanning"))
        time = datetime.datetime.fromtimestamp(val['start']).strftime('%c') + " to " + datetime.datetime.fromtimestamp(val['end']).strftime('%c')
        print(time)
        print("Current ports affected: ")
        print(portList)
        print("\n")
    flagString = ""
    if 'flags' in val:
        x = val['flags']
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80
        if x & FIN:
            flagString = flagString + "FIN "
        if x & SYN:
            flagString = flagString + "SYN "
        if x & RST:
            flagString = flagString + "RST "
        if x & PSH:
            flagString = flagString + "PSH "
        if x & ACK:
            flagString = flagString + "ACK "
        if x & URG:
            flagString = flagString + "URG "
        if x & ECE:
            flagString = flagString + "ECE "
        if x & CWR:
            flagString = flagString + "CWR "
        print(flagString)