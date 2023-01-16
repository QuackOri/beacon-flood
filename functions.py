import random


def btoi(bytes_array):
    assert isinstance(bytes_array, bytes), '{} is not bytes'.format(bytes_array)
    return int.from_bytes(bytes_array, byteorder='little')

def itobl(number, length):
    assert isinstance(number, int), '{} is not int'.format(number)
    return number.to_bytes(length, byteorder='little')

def itobb(number, length):
    assert isinstance(number, int), '{} is not int'.format(number)
    return number.to_bytes(length, byteorder='big')  

def make_ssid_bytes(ssid):
    assert len(ssid) <= 0xff, 'ssid is too long. -> {}'.format(ssid)
    return b'\x00' + itobb(len(ssid), 1) + ssid.encode('utf-8')

def make_random_mac():
    mac_bytes = b''
    for _ in range(6):
        mac_byte = random.randrange(0x10, 0xf0).to_bytes(1, byteorder='big')
        mac_bytes += mac_byte
    return mac_bytes
