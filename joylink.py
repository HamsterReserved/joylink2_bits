#!/usr/bin/python3

# Part of architecture from python-broadlink (https://github.com/mjg59/python-broadlink).
# Thanks!

import os
import time
import socket
import sys
import struct
import json
import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve, EllipticCurvePublicKey, _CURVE_TYPES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import register_interface

# Hack to add support for secp160r1
@register_interface(EllipticCurve)
class SECP160R1(object):
    name = "secp160r1"
    key_size = 160


_CURVE_TYPES["secp160r1"] = SECP160R1


def compress_pubkey(public_key: EllipticCurvePublicKey):
    uncompressed = public_key.public_numbers().encode_point()
    key_size = public_key.curve.key_size
    return bytes([2 + (uncompressed[-1] & 1)]) + uncompressed[1:key_size // 8 + 1]


def uncompress_pubkey_secp160r1(public_key: bytes):
    p = 0xffffffffffffffffffffffffffffffff7fffffff  # modulo
    b = 0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45
    x = int.from_bytes(public_key[1:], "big")
    y_sq = pow(x, 3, p) - (3 * x) % p + b  # y^2 = x^3 -3x + b
    y = pow(y_sq, (p + 1) >> 2, p)  # square_root as power
    y_bytes = y.to_bytes(20, "big")  # secp160r1 has 160 bits key size
    if public_key[0] & 1 != y_bytes[0] & 1:
        y_bytes = (-y % p).to_bytes(20, "big")  # adjust sign
    return b"\x04" + public_key[1:] + y_bytes


# These are single-shot, no state saving
def aes_encrypt(payload, cipher):
    padder = padding.PKCS7(128).padder()  # AES block size
    padded_payload = padder.update(payload) + padder.finalize()

    encryptor = cipher.encryptor()
    return encryptor.update(padded_payload) + encryptor.finalize()


def aes_decrypt(payload, cipher):
    decryptor = cipher.decryptor()
    padded_payload = decryptor.update(payload) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()  # AES block size
    return unpadder.update(padded_payload) + unpadder.finalize()


def crc16(payload):
    crc = 0xffff
    for byte in payload:
            crc = (crc >> 8) | ((crc << 8) & 0xff00)
            crc ^= byte
            crc ^= (crc & 0xff) >> 4
            crc ^= (crc << 12) & 0xffff
            crc ^= (crc & 0xff) << 5
    return crc


def discover(timeout=None, local_ip_address=None):
    if local_ip_address is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # connecting to a UDP address doesn't send packets
            s.connect(('8.8.8.8', 53))
            local_ip_address = s.getsockname()[0]
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    cs.bind((local_ip_address, 0))
    starttime = time.time()

    devices = []
    payload = "{}"

    packet = joylink_packet.new(
        None, payload, joylink_packet.ENCRYPTION_CLEAR_TEXT, joylink_packet.TYPE_DEVICE_DISCOVERY)
    packet_bytes = packet.encode(None)

    cs.sendto(packet_bytes, ('255.255.255.255', 80))
    if timeout is None:
        response = cs.recvfrom(1024)
        host = response[1]
        response_packet = joylink_packet.parse(response[0], None)
        response_json = response_packet.extract_jsonobj()

        dev_pubkey = bytes.fromhex(response_json["devkey"])
        feedid = response_json["feedid"]
        productuuid = response_json["productuuid"]

        return joylink_device(host, dev_pubkey, feedid, productuuid)
    else:
        while (time.time() - starttime) < timeout:
            cs.settimeout(timeout - (time.time() - starttime))
            try:
                response = cs.recvfrom(1024)
            except socket.timeout:
                return devices
            host = response[1]
            response_packet = joylink_packet.parse(response[0], None)
            response_json = response_packet.extract_jsonobj()

            dev_pubkey = bytes.fromhex(response_json["devkey"])
            feedid = response_json["feedid"]
            productuuid = response_json["productuuid"]

            devices.append(joylink_device(host, dev_pubkey, feedid, productuuid))
        return devices


class joylink_packet:
    ENCRYPTION_CLEAR_TEXT = 0
    ENCRYPTION_STATIC_AES = 1
    ENCRYPTION_ECDH = 2
    ENCRYPTION_DYNAMIC_AES = 3

    TYPE_DEVICE_DISCOVERY = 1
    TYPE_DEVICE_AUTH = 2
    TYPE_DEVICE_CONTROL_JSON = 3
    TYPE_DEVICE_CONTROL_BIN = 4

    @staticmethod
    def new(opt, payload, encryption, p_type):
        packet = joylink_packet()

        if isinstance(opt, str):
            opt = opt.encode("utf-8")

        if opt is None:
            opt = b""

        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if payload is None:
            payload = b""

        packet.magic = 0x123455bb  # LAN access
        packet.version = 1
        packet.type = p_type
        packet.frag_index = 0
        packet.frag_total = 0
        packet.encryption = encryption
        packet.opt = opt
        packet.payload = payload
        return packet
        # Remaining fields and encryption will done in encode()

    # Parse incoming data. `device` is for decryption
    @staticmethod
    def parse(buf, cipher):
        if len(buf) < 16:  # JoyLink 2.0 has a 16-byte header
            return None

        packet = joylink_packet()

        (packet.magic,
         optlen,
         payloadlen,
         packet.version,
         packet.p_type,
         packet.frag_total,
         packet.frag_index,
         packet.encryption,
         _,  # reserved
         p_crc16) = struct.unpack("<IHHBBBBBBH", buf[0:16])

        if packet.magic != 0x123455bb:  # LAN access magic
            return None

        opt = b""
        if len(buf) - 16 >= optlen:
            opt = buf[16:16 + optlen]
        else:
            print("Error: short read on opt")
            return None

        payload = b""
        if len(buf) - 16 - optlen >= payloadlen:
            payload = buf[16 + optlen:16 + optlen + payloadlen]
        else:
            print("Error: short read on payload")
            return None

        if p_crc16 != crc16(opt + payload):
            print("Warning: CRC16 mismatch: expected 0x%x, got 0x%x" %
                  (crc16(opt + payload), p_crc16))

        if packet.encryption != packet.ENCRYPTION_CLEAR_TEXT:
            payload = aes_decrypt(payload, cipher)

        packet.opt = opt
        packet.payload = payload
        return packet

    def encode(self, cipher):
        if self.encryption != self.ENCRYPTION_CLEAR_TEXT:
            self.payload = aes_encrypt(self.payload, cipher)

        packet = struct.pack("<IHHBBBBBBH",
                             self.magic,
                             len(self.opt),
                             len(self.payload),
                             self.version,
                             self.type,
                             self.frag_total,
                             self.frag_index,
                             self.encryption,
                             0,
                             crc16(self.opt + self.payload))
        return packet + self.opt + self.payload

    # Call this with device.cipher initialized if encryption is requested
    def send(self, device, timeout):
        packet = self.encode(device.cipher)
        device.cs.sendto(packet, device.host)
        device.cs.settimeout(timeout)

        try:
            response = device.cs.recvfrom(2048)
        except socket.timeout:
            return None

        return joylink_packet.parse(response[0], device.cipher)

    def send_with_timestamp(self, device, timeout):
        self.payload = int(time.time()).to_bytes(4, "little") + self.payload
        return self.send(device, timeout)

    # Helper
    def extract_jsonobj(self, offset = 0):
        json_str = self.payload[offset:]
        return json.loads(json_str.decode("utf-8"))


class joylink_device:
    def __init__(self, host, compressed_pubkey, feedid, productuuid):
        self.host = host
        self.feedid = feedid
        self.productuuid = productuuid

        uncompressed_dev_pubkey = uncompress_pubkey_secp160r1(
            compressed_pubkey)
        self.dev_pubkey = ec.EllipticCurvePublicNumbers.from_encoded_point(
            SECP160R1(), uncompressed_dev_pubkey).public_key(default_backend())

        self.cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.cs.bind(('', 0))

        self.privkey = ec.generate_private_key(SECP160R1(), default_backend())
        self.pubkey = self.privkey.public_key()

    def auth(self):
        # This key is only used to encrypy this packet.
        # Later packets are encrypted by `localkey` below.
        aeskey = self.privkey.exchange(ec.ECDH(), self.dev_pubkey)

        localkey = binascii.b2a_hex(os.urandom(16)).decode("utf-8")
        accesskey = binascii.b2a_hex(os.urandom(16)).decode("utf-8")

        auth_dict = {
            "data": {
                "feedid": self.feedid,
                "productuuid": self.productuuid,
                "accesskey": accesskey,  # not used, just throw away the key
                "localkey": localkey,
                "server": ["not.wanna.seeme:2001"],
                "tcpaes": ["not.wanna.seeme:2014"],
                "joylink_server": ["not.wanna.seeme:6001"],
                "lancon": 1
            }
        }

        self.cipher = Cipher(algorithms.AES(aeskey[0:16]), modes.CBC(
            aeskey[4:20]), backend=default_backend())

        packet = joylink_packet.new(compress_pubkey(self.pubkey), json.dumps(
            auth_dict), joylink_packet.ENCRYPTION_ECDH, joylink_packet.TYPE_DEVICE_AUTH)
        response = packet.send_with_timestamp(self, 10)

        if response is None:
            print("Error: Authentication failed")
            return False

        if response.extract_jsonobj(4)["msg"] == "success": # Skip timestamp
            localkey_bytes = localkey.encode("utf-8")
            self.cipher = Cipher(algorithms.AES(localkey_bytes[0:16]), modes.CBC(
                localkey_bytes[16:32]), backend=default_backend())

            return True
        else:
            print("Error: Authentication failed (returned: %s)" % (response.payload,))
            return False

    def send_script(self, script, biz_code=1002):
        payload = biz_code.to_bytes(4, "little")  # type: control request
        # this does not need to be contigious (in fact, contigious seq causes problems if this program restarts)
        payload += os.urandom(4)
        payload += script

        packet = joylink_packet.new(
            None, payload, joylink_packet.ENCRYPTION_DYNAMIC_AES, joylink_packet.TYPE_DEVICE_CONTROL_BIN)
        response = packet.send_with_timestamp(self, 3)

        print(response.payload)
