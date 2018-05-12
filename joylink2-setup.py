import socket
import struct
import sys
import time
from socket import AF_INET, SOCK_DGRAM, socket


def send_byte(sock, byte_type, pos, byte, dest_port=65432):
    dest_addr = "239.%d.%d.%d" % (byte_type, pos, byte)
    # byte is encoded to address, \0 has no use here
    sock.sendto(b"\0", (dest_addr, dest_port))


# src_port does not matter at all. All we need is the destination address
def setup(ssid, pwd, local_address=None, src_port=12345):
    if local_address is None:
        s = socket(AF_INET, SOCK_DGRAM)
        # connecting to a UDP address doesn't send packets
        s.connect(('8.8.8.8', 53))
        local_address = s.getsockname()[0]
        s.close()
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((local_address, src_port))

    payload_initial = b"\0\0\0\0\0"
    payload_lengths = len(ssid).to_bytes(1, "little") + \
        len(pwd).to_bytes(1, "little")
    payload_ssid = ssid.encode("utf-8")
    payload_pwd = pwd.encode("utf-8")
    payload_checksum = ((sum(
        payload_lengths + payload_ssid + payload_pwd) + 10) & 0xff).to_bytes(1, "little")  # Magic 10

    while True:
        sent_bytes = 1

        for byte in payload_initial:
            send_byte(sock, 0x76, sent_bytes, byte)
            sent_bytes += 1

        for byte in payload_lengths:
            send_byte(sock, 0x77, sent_bytes, byte)
            sent_bytes += 1

        for byte in payload_ssid:
            send_byte(sock, 0x78, sent_bytes, byte)
            sent_bytes += 1

        for byte in payload_pwd:
            send_byte(sock, 0x79, sent_bytes, byte)
            sent_bytes += 1

        for byte in payload_checksum:
            send_byte(sock, 0x7a, sent_bytes, byte)
            sent_bytes += 1
        time.sleep(1)


if __name__ == "__main__":
    # python joylink2-setup.py <ssid> <password> [local ip address]
    setup(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
