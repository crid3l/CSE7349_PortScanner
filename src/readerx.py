#this program accepts packets inputted 

from scapy.all import *
import datetime
import socket  
import sys


sourcePorts = {}

def parsePacketList(packets, IPAddr):
    global sourcePorts

    # Let's iterate through every packet
    for packet in packets:
        # print("$$$$$*****PACKET-BEGIN*****$$$$$")

        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            else:
                #print(layer.name)
                counter = counter + 1

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
            #print("IP source " + IP.src)
            if IP.dst == IPAddr:
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
            print("Current ports affected: ")
            print(portList)
            print("\n")


def main():
    print("Starting live Scan")
    print("Press any key to exit")
    
    count = 0
    hostname = socket.gethostname()    
    IPAddr = socket.gethostbyname(hostname) 
    print("Host IP to protect " + IPAddr)
    print("Analyzing packets ...")

    while True:
        try:
            #packets = rdpcap("tcp_syn_scan.pcapng")
            packets = sniff(filter="tcp", count = 100)
            parsePacketList(packets, IPAddr)
            count = count + 1

        except KeyboardInterrupt:
            print('Interrupted')
            try:
                exit()
                sys.exit(0)
            except SystemExit:
                os._exit(0)




if __name__ == '__main__':
    main()