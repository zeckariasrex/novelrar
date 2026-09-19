"""RAR5 method-0 writer from RARLAB's public container description.
Stores bytes verbatim; does not implement the RAR compression algorithm.
"""
import struct
import zlib
from safe_output import member_parts

def _vint(n):
    result=bytearray()
    while n>=128: result.append((n&127)|128); n>>=7
    result.append(n)
    return bytes(result)

def _block(kind,body,data=None):
    header=_vint(kind)+_vint(2 if data is not None else 0)
    if data is not None: header+=_vint(len(data))
    header+=body
    header=_vint(len(header))+header
    return struct.pack('<I',zlib.crc32(header)&0xffffffff)+header+(data or b'')

def create(entries):
    out=bytearray(b'Rar!\x1a\x07\x01\x00'+_block(1,_vint(0)))
    for name,data in entries.items():
        member_parts(name)
        name=name.encode('utf-8'); data=bytes(data)
        body=(_vint(4)+_vint(len(data))+_vint(0o100644)+
              struct.pack('<I',zlib.crc32(data)&0xffffffff)+
              _vint(0)+_vint(1)+_vint(len(name))+name)
        out.extend(_block(2,body,data))
    out.extend(_block(5,_vint(0)))
    return bytes(out)
