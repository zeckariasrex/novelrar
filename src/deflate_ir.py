"""Experimental two-stage RFC1951 decoder: parse commands, execute native LZ IR.
Original parser reuses this repository's canonical Huffman helpers. No zlib
used to produce decoded output. Tokenization can cost more than it saves.
"""
import ctypes as C
from geex_unpack import (BitReader,_codes_lsb,_read_sym,_fixed_lit_lengths,
                         _fixed_dist_lengths,_inflate_dynamic,LEN_BASE,LEN_EXTRA,
                         DIST_BASE,DIST_EXTRA)
from native_lz4 import _library,MODES

class Command(C.Structure):
    _fields_=[(name,C.c_size_t) for name in ('offset','literals','distance','length')]

def tokenize(data,max_output=64<<20):
    if not 0<=max_output<=256<<20: raise ValueError('invalid output limit')
    br=BitReader(data); literals=bytearray(); commands=[]; size=anchor=0
    def literal(block):
        nonlocal size
        if len(block)>max_output-size: raise ValueError('output limit')
        literals.extend(block);size+=len(block)
    last=0
    while not last:
        last=br.bits(1);kind=br.bits(2)
        if kind==3: raise ValueError('reserved block type')
        if kind==0:
            br.align(); length=br.bits(16); inverse=br.bits(16)
            if length^inverse!=65535: raise ValueError('stored length mismatch')
            if br.i+length>len(data): raise ValueError('truncated stored block')
            literal(data[br.i:br.i+length]);br.i+=length
            continue
        ll,dd=(_fixed_lit_lengths(),_fixed_dist_lengths()) if kind==1 else _inflate_dynamic(br)
        lt,lm=_codes_lsb(ll);dt,dm=_codes_lsb(dd)
        while True:
            sym=_read_sym(br,lt,lm)
            if sym==256: break
            if sym<256: literal(bytes([sym]));continue
            if sym>285: raise ValueError('reserved length code')
            idx=sym-257;length=LEN_BASE[idx]+br.bits(LEN_EXTRA[idx])
            dsym=_read_sym(br,dt,dm)
            if dsym>29: raise ValueError('reserved distance code')
            distance=DIST_BASE[dsym]+br.bits(DIST_EXTRA[dsym])
            if distance>size or length>max_output-size: raise ValueError('invalid match/output limit')
            commands.append((anchor,len(literals)-anchor,distance,length))
            anchor=len(literals);size+=length
    commands.append((anchor,len(literals)-anchor,0,0))
    if br.i!=len(data): raise ValueError('trailing DEFLATE bytes')
    return bytes(literals),commands,size

def execute(literals,commands,size,mode='grow'):
    import platform
    if not 0<=size<=256<<20 or mode not in MODES: raise ValueError('invalid execution options')
    if mode in ('asm','sse2') and platform.machine() not in ('x86_64','AMD64'):
        raise ValueError('instruction set requires x86-64')
    if any(any(x<0 for x in c) for c in commands): raise ValueError('negative command field')
    array=(Command*len(commands))(*(Command(*c) for c in commands))
    output=C.create_string_buffer(max(1,size));written=C.c_size_t()
    fn=_library().nr_execute
    fn.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(Command),C.c_size_t,C.c_void_p,
                 C.c_size_t,C.c_int,C.POINTER(C.c_size_t)]
    fn.restype=C.c_int
    if fn(literals,len(literals),array,len(commands),output,size,MODES[mode],C.byref(written)):
        raise ValueError('invalid LZ commands or output overflow')
    if written.value!=size: raise ValueError('output length mismatch')
    return output.raw[:size]

def decompress(data,max_output=64<<20,mode='grow'):
    literals,commands,size=tokenize(data,max_output)
    return execute(literals,commands,size,mode)
