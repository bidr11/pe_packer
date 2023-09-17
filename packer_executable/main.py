import argparse
import lief
import os
import zlib
import struct
from Crypto.Cipher import AES

KEY = b"0123456789abcdef"
IV = b"abcdef9876543210"

def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))


def pad(plain_text):
    block_size = AES.block_size;
    number_of_bytes_to_pad = block_size - len(plain_text) % block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text = plain_text + padding_str.encode()
    return padded_plain_text
    

def encrypt(plain_text):
    plain_text = pad(plain_text)
    iv = IV
    key = KEY
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(plain_text)
    return encrypted_text

def pack_data(data):
    size = len(data)
    decompressed_size = struct.pack("<I", size)
    compressed_data = decompressed_size + zlib.compress(data, 2)

    size = len(compressed_data)
    compressed_size = struct.pack("<I", size)
    
    return compressed_size + encrypt(compressed_data)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Pack PE binary')
    parser.add_argument('input', metavar="FILE", help='input file')
    parser.add_argument('-p', metavar="UNPACKER", help='unpacker executable', default="stub.exe")
    parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")

    args = parser.parse_args()

    # open the unpack.exe binary
    unpack_PE = lief.PE.parse(args.p)

    file_alignment = unpack_PE.optional_header.file_alignment
    section_alignment = unpack_PE.optional_header.section_alignment

    # then create the a .packed section, with the packed PE inside :

    # read the whole file to be packed
    with open(args.input, "rb") as f:
        input_PE_data = f.read()

    # create the section in lief
    packed_data = list(pack_data(input_PE_data))  # pack the input file data

    packed_data = pad_data(packed_data,
                           file_alignment)  # pad with 0 to align with file alignment

    packed_section = lief.PE.Section(".packed")
    packed_section.content = packed_data
    packed_section.size = len(packed_data)
    packed_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                      | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                                      | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    
    # We don't need to specify a Relative Virtual Address here, lief will just put it at the end.
    unpack_PE.add_section(packed_section)

    # Lief will compute this for us.
    unpack_PE.optional_header.sizeof_image = 0

    # save the resulting PE
    if os.path.exists(args.o):
        os.remove(args.o)

    builder = lief.PE.Builder(unpack_PE)
    builder.build()
    builder.write(args.o)
