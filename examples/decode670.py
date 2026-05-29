#!/usr/bin/env python3
import sys
import argparse
import struct
import zlib
from os import stat
from io import BytesIO
from hashlib import sha256
from Cryptodome.Cipher import AES

"""Magic number constants from ZTE routers"""
PAYLOAD_MAGIC = 0x01020304
SIGNATURE_MAGIC = 0x04030201
ZTE_MAGIC = (0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA)
ZTE_IV = b'ZTE%FN$GponNJ025'


class zteUtil():
    def read_header(infile, little_endian=False):
        """expects to be at position 0 of the file, returns size of header"""
        header_magic = struct.unpack('>4I', infile.read(16))
        if header_magic == ZTE_MAGIC:
            # 128 byte header
            endian = '<' if little_endian else '>'
            header = struct.unpack(endian + '28I', infile.read(112))
            assert header[2] == 4
            header_length = header[13]
            signed_config_size = header[14]
            file_size = stat(infile.name).st_size
            assert header_length + signed_config_size == file_size, "file size does not match header"
        else:
            # no extra header so return to start of the file
            infile.seek(0)
        return infile.tell()

    def read_signature(infile):
        """expects to be at the start of the signature magic, returns
        (signature, bytes read)"""
        signature_header = struct.unpack('>3I', infile.read(12))
        signature = b''
        if signature_header[0] == SIGNATURE_MAGIC:
            # _ = signature_header[1] # 0 ?
            signature_length = signature_header[2]
            signature = infile.read(signature_length)
        else:
            # no signature so return to start of the file
            infile.seek(0)
        return signature

    def read_payload(infile, raise_on_error=True):
        """expects to be at the start of the payload magic"""
        payload_header = struct.unpack('>15I', infile.read(60))
        if payload_header[0] != PAYLOAD_MAGIC:
            if raise_on_error:
                raise ValueError("Payload header does not start with the payload magic.")
            else:
                return None
        return payload_header

    def read_payload_type(infile, raise_on_error=True):
        """expects to be at the start of the payload magic"""
        payload_header = zteUtil.read_payload(infile, raise_on_error)
        return payload_header[1] if payload_header is not None else None

    def mac_to_str(mac):
        if not len(mac):
            return ''
        if not isinstance(mac, bytes):
            mac = mac.strip().replace(':','')
            if len(mac) != 12:
                raise ValueError("MAC address string has wrong length")
            mac = bytes.fromhex(mac)
        if len(mac) != 6:
            raise ValueError("MAC address has wrong length")
        return "%02x%02x%02x%02x%02x%02x" % (mac[5], mac[4], mac[3], mac[2], mac[1], mac[0])


class zteXcryptor():
    # type 3/4 encryption, AES256CBC with the key/IV set from SHA256 hashes
    force_same_data_length = False
    aes_key_str = None
    aes_iv_str = None

    def set_key(self, aes_key=None, aes_iv=None):
        if aes_key is None:
            self.aes_cipher = None
            return

        if isinstance(aes_key, bytes):
            self.aes_key_str = aes_key.decode()
        else:
            self.aes_key_str = aes_key

        if aes_iv is None:
            self.aes_iv_str = self.aes_key_str
        elif isinstance(aes_iv, bytes):
            self.aes_iv_str = aes_iv.decode()
        else:
            self.aes_iv_str = aes_iv

        key = sha256(self.aes_key_str.encode()).digest()
        iv = sha256(self.aes_iv_str.encode()).digest()
        self.aes_cipher = AES.new(key, AES.MODE_CBC, iv[:16])

    def read_chunks(self, infile):
        encrypted_data = BytesIO()
        total_dec_size = 0
        while True:
            dec_size, chunk_size, more_data = struct.unpack(">3I", infile.read(12))
            encrypted_data.write(infile.read(chunk_size))
            total_dec_size += dec_size
            if more_data == 0:
                break
        encrypted_data.seek(total_dec_size)
        return encrypted_data

    def decrypt(self, infile):
        data = self.read_chunks(infile)
        data_size = data.tell()
        data.seek(0)
        res = BytesIO()
        res.write(self.aes_cipher.decrypt(data.read())[:data_size])
        res.seek(0)
        return res


class zteCompression():
    def decompress(infile):
        """decompress a block, return data and crc
        A 'block' consists of a 12 byte (3x4-byte INT) header and a ZLIB payload
        HEADER
            [XXXX] Decompressed length of block (bytes)
            [XXXX] Compressed length of block (bytes)
            [XXXX] 0 if last block else cumulative compressed blocks length
        PAYLOAD
            [....] ZLIB chunk
        """
        decompressed_data = BytesIO()
        crc = 0
        while True:
            aes_header = struct.unpack('>3I', infile.read(12))
            decompressed_length = aes_header[0]
            compressed_length = aes_header[1]
            compressed_chunk = infile.read(compressed_length)
            crc = zlib.crc32(compressed_chunk, crc)
            decompressed_chunk = zlib.decompress(compressed_chunk)
            assert decompressed_length == len(decompressed_chunk)
            decompressed_data.write(decompressed_chunk)
            if aes_header[2] == 0:
                break
        decompressed_data.seek(0)
        return (decompressed_data, crc)


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description="Decode config.bin from ZTE Routers",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", type=argparse.FileType("rb"),
                        help="Encoded configuration file e.g. config.bin")
    parser.add_argument("outfile", type=argparse.FileType("wb"),
                        help="Output file e.g. config.xml")
    parser.add_argument("--mac", type=str, default="",
                        help="Router MAC address")
    parser.add_argument("--sn", type=str, default="",
                        help="Router serial number")
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile


    zteUtil.read_header(infile, True)
    signature = zteUtil.read_signature(infile).decode()
    if signature:
        print("Detected signature: %s" % signature)
    payload_type = zteUtil.read_payload_type(infile)
    print("Detected payload type %d" % payload_type)
    start_pos = infile.tell()

    matched = False
    if payload_type == 6:
        if args.mac is None or args.sn is None:
            error("mac, sn cannot be null" % len(generated))

        print("MAC: %s\nS/N: %s" % (args.mac, args.sn))
        user_key = args.sn[4:] + zteUtil.mac_to_str(args.mac)
        decryptor = zteXcryptor()
        decryptor.set_key(user_key.encode(), ZTE_IV)
        infile.seek(start_pos)
        decrypted = decryptor.decrypt(infile)
        if zteUtil.read_payload_type(decrypted, raise_on_error=False) is not None:
            matched = True
            infile = decrypted

        if matched is None:
            error("Failed to decrypt type 6 payload, tried %d generated key(s)!" % len(generated))
            return 1
    elif payload_type == 0:
        pass
    else:
        error("Unknown payload type %d encountered!" % payload_type)
        return 1

    res, _ = zteCompression.decompress(infile)
    outfile.write(res.read())

    if matched:
        print("\nSuccessfully decrypted!")

    return 0


def error(err):
    print(err, file=sys.stderr)


if __name__ == "__main__":
    main()
