from dataclasses import dataclass
from struct import *

@dataclass
class Dot11Beacon:
    frame_control: int
    duration_id: int
    DA: bytes
    SA: bytes  
    BSS_ID: bytes 
    sequence_control: int

    def __len__(self):
        return 24

    def ctob(self):
        return pack('<HH6s6s6sH', self.frame_control, self.duration_id, self.DA, self.SA, self.BSS_ID, self.sequence_control)

@dataclass
class Dot11WirelessManagement:
    timestamp: int 
    beacon_interval: int 
    capability_information: int
    tag_field: bytes

    def __len__(self):
        return 12 + len(self.tag_field)

    def ctob(self):
        return pack('<QHH{}s'.format(len(self.tag_field)), self.timestamp, self.beacon_interval, self.capability_information, self.tag_field)

@dataclass
class Beacon:
    beacon_frame: Dot11Beacon
    wireless_management: Dot11WirelessManagement

    def ctob(self):
        return self.beacon_frame.ctob() + self.wireless_management.ctob()

def parse_dot11B(packet):
    a, b, c, d, e, f = unpack('<HH6s6s6sH', packet[:24])
    return Dot11Beacon(a, b, c, d, e, f)

def parse_dot11WM(packet):
    a, b, c = unpack('<QHH', packet[:12])
    return Dot11WirelessManagement(a, b, c, packet[12:])

def parse(packet):
    return Beacon(
        parse_dot11B(packet),
        parse_dot11WM(packet[24:])
    )

# target = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'
# beacon = parse(target)
# print(beacon)
# result = beacon.ctob()
# print(target == result)