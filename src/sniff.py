from scapy.all import *


from collections import Counter
from scapy.all import sniff
 
## Create a Packet Counter
packet_counts = Counter()
 
## Define our Custom Action function
def custom_action(packet):
   packet.show()
   print ("end of packet ---------------")
 
## Setup sniff, filtering for IP traffic
p = sniff(filter="tcp", prn=custom_action)
 
## Print out packet count per A <--> Z address pair
print("done")
 
 