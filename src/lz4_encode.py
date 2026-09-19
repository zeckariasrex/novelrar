"""Independent greedy LZ4 encoder from the published block/frame grammars.
No external implementation code is used. Writes independent 64 KiB blocks.
"""
import struct
from lz4_frame import xxh32

def _extra(n):
    return b'\xff' * (n // 255) + bytes([n % 255])

def compress_block(data):
    data = bytes(data)
    out, table = bytearray(), {}
    anchor = i = 0
    n = len(data)
    while i <= n - 12:
        key = data[i:i+4]
        previous = table.get(key)
        table[key] = i
        if previous is None or i-previous > 65535:
            i += 1
            continue
        length = 4
        while i+length < n-5 and data[previous+length] == data[i+length]:
            length += 1
        literals = i-anchor
        out.append((min(literals,15)<<4) | min(length-4,15))
        if literals >= 15: out.extend(_extra(literals-15))
        out.extend(data[anchor:i])
        out.extend(struct.pack('<H',i-previous))
        if length >= 19: out.extend(_extra(length-19))
        i += length
        anchor = i
    literals = n-anchor
    out.append(min(literals,15)<<4)
    if literals >= 15: out.extend(_extra(literals-15))
    out.extend(data[anchor:])
    return bytes(out)

def compress(data):
    data = bytes(data)
    desc = bytes([0x6c, 0x40]) + struct.pack('<Q',len(data))
    out = bytearray(b'\x04\x22\x4d\x18' + desc + bytes([(xxh32(desc)>>8)&255]))
    for i in range(0,len(data),65536):
        raw = data[i:i+65536]
        encoded = compress_block(raw)
        if len(encoded) >= len(raw):
            out.extend(struct.pack('<I',len(raw) | 0x80000000)); out.extend(raw)
        else:
            out.extend(struct.pack('<I',len(encoded))); out.extend(encoded)
    out.extend(struct.pack('<II',0,xxh32(data)))
    return bytes(out)
