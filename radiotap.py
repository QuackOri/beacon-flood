from dataclasses import dataclass
from struct import *

@dataclass
class Radiotap:
    version: int
    pad: int
    length: int
    present: int

    def skip(self, packet):
        return packet[self.length:]

    def ctob(self):
        return pack('<BBHI', self.version, self.pad, self.length, self.present)
        

# def parse(packet):
#     return Radiotap(
#         packet[0],
#         packet[1],
#         btoi(packet[2:4]),
#         btoi(packet[4:8])
#     )

def parse(packet):
    version, pad, length, present = unpack('<BBHI', packet)
    return Radiotap(version, pad, length, present)
