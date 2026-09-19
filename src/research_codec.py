"""Bounded stream codecs, adaptive prediction, and authenticated NRX1 envelopes.

NRX1 is a new experimental format, NOT RAR/ZIP/7z encryption. Primitives are
provided by cryptography; no homemade cipher. Optional dependency loaded lazily.
"""
from __future__ import annotations
import bz2
import hashlib
import hmac
import io
import lzma
import os
import struct
import zipfile
import zlib

DEFAULT_LIMIT = 64 << 20
CODECS = ('store', 'deflate', 'zlib', 'gzip', 'bzip2', 'xz', 'lz4', 'adaptive')
HEADER = struct.Struct('<4sBQ32s')  # magic, method, original length, SHA-256

def _limit(value):
    if not isinstance(value, int) or not 0 <= value <= 256 << 20:
        raise ValueError('output limit must be in [0, 256 MiB]')

def compress(data: bytes, codec='zlib') -> bytes:
    data = bytes(data)
    if codec == 'store': return data
    if codec in ('deflate','zlib','gzip'):
        enc = zlib.compressobj(6, zlib.DEFLATED, {'deflate':-15,'zlib':15,'gzip':31}[codec])
        return enc.compress(data)+enc.flush()
    if codec == 'bzip2': return bz2.compress(data)
    if codec == 'xz': return lzma.compress(data)
    if codec == 'lz4':
        from lz4_encode import compress as encode
        return encode(data)
    if codec == 'adaptive': return adaptive_compress(data)
    raise ValueError('unsupported codec: '+codec)

def decompress(data: bytes, codec='zlib', max_output=DEFAULT_LIMIT) -> bytes:
    _limit(max_output)
    if codec == 'adaptive': return adaptive_decompress(data,max_output)
    if codec == 'store':
        if len(data)>max_output: raise ValueError('output limit exceeded')
        return bytes(data)
    if codec == 'lz4':
        import lz4_frame
        return lz4_frame.decompress(data, max_output=max_output)
    if codec in ('deflate','zlib','gzip'):
        dec = zlib.decompressobj({'deflate':-15,'zlib':15,'gzip':31}[codec])
    elif codec == 'bzip2': dec = bz2.BZ2Decompressor()
    elif codec == 'xz': dec = lzma.LZMADecompressor(memlimit=128<<20)
    else: raise ValueError('unsupported codec: '+codec)
    # One extra byte detects expansion beyond the allowance. No unbounded flush.
    raw = dec.decompress(data,max_output+1)
    if len(raw)>max_output: raise ValueError('output limit exceeded')
    if not dec.eof: raise ValueError('truncated stream or output limit exceeded')
    if dec.unused_data: raise ValueError('trailing data/concatenated streams unsupported')
    return raw

def _predict(data, stride, inverse=False):
    out = bytearray(data)
    for i in range(stride,len(data)):
        out[i] = data[i] ^ (out[i-stride] if inverse else data[i-stride])
    return bytes(out)

def adaptive_compress(data):
    # All candidates include their metadata before selection. Store is a fallback.
    candidates = [(0,data),(1,zlib.compress(data)),(2,bz2.compress(data)),
                  (3,lzma.compress(data))]
    for stride in (1,16,64,256):
        if len(data)>stride:
            candidates.append((4,struct.pack('<H',stride)+zlib.compress(_predict(data,stride))))
    method, payload = min(candidates,key=lambda item:len(item[1]))
    return HEADER.pack(b'NA01',method,len(data),hashlib.sha256(data).digest())+payload

def adaptive_decompress(blob,max_output=DEFAULT_LIMIT):
    _limit(max_output)
    if len(blob)<HEADER.size: raise ValueError('truncated adaptive header')
    magic, method, size, digest = HEADER.unpack_from(blob)
    if magic!=b'NA01' or size>max_output: raise ValueError('invalid header/output limit')
    payload=blob[HEADER.size:]
    if method in (0,1,2,3):
        raw=decompress(payload,('store','zlib','bzip2','xz')[method],size)
    elif method==4:
        if len(payload)<2: raise ValueError('truncated predictor')
        stride=struct.unpack_from('<H',payload)[0]
        if stride not in (1,16,64,256): raise ValueError('unsupported predictor')
        raw=_predict(decompress(payload[2:],'zlib',size),stride,True)
    else: raise ValueError('unsupported adaptive method')
    if len(raw)!=size or not hmac.compare_digest(hashlib.sha256(raw).digest(),digest):
        raise ValueError('adaptive length/checksum mismatch')
    return raw

def create_zip(entries,codec='deflate'):
    methods={'store':0,'deflate':8,'bzip2':12,'lzma':14}
    if codec not in methods: raise ValueError('unsupported ZIP method')
    from safe_output import member_parts
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=methods[codec]) as archive:
        for name,data in entries.items():
            member_parts(name)
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
            info.compress_type=methods[codec]
            archive.writestr(info,data)
    return stream.getvalue()

def _key(password,salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    if not isinstance(password,bytes) or not password:
        raise ValueError('password must be nonempty bytes')
    # Fixed costs: untrusted headers cannot request arbitrary CPU/memory work.
    return Scrypt(salt=salt,length=32,n=1<<14,r=8,p=1).derive(password)

def encrypt(data,password,codec='adaptive'):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if codec not in CODECS: raise ValueError('unsupported codec')
    if len(data)>DEFAULT_LIMIT: raise ValueError('envelope input limit exceeded')
    salt,nonce=os.urandom(16),os.urandom(12)
    header=b'NRX1'+bytes([CODECS.index(codec)])+salt+nonce
    return header+AESGCM(_key(password,salt)).encrypt(nonce,compress(data,codec),header)

def decrypt(blob,password,max_output=DEFAULT_LIMIT):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _limit(max_output)
    if len(blob)<49 or len(blob)>2*DEFAULT_LIMIT or blob[:4]!=b'NRX1' or blob[4]>=len(CODECS):
        raise ValueError('invalid NRX1 envelope')
    header=blob[:33]
    try: packed=AESGCM(_key(password,blob[5:21])).decrypt(blob[21:33],blob[33:],header)
    except InvalidTag as exc:
        raise ValueError('wrong password or corrupted envelope') from exc
    return decompress(packed,CODECS[blob[4]],max_output)


def transform_stream(source, sink, codec='zlib', *, decode=False,
                     max_output=DEFAULT_LIMIT, chunk_size=65536):
    """Incremental zlib/gzip/raw-DEFLATE processing with bounded output chunks.

    Writes are provisional until return: callers needing atomic publication
    should supply a temporary sink. Does not handle concatenated gzip members.
    Returns total output bytes; input/output are binary file-like objects.
    """
    _limit(max_output)
    if codec not in ('deflate','zlib','gzip') or not 1<=chunk_size<=1<<20:
        raise ValueError('unsupported streaming codec/chunk size')
    wbits={'deflate':-15,'zlib':15,'gzip':31}[codec]
    engine=zlib.decompressobj(wbits) if decode else zlib.compressobj(wbits=wbits)
    total=0
    def emit(data):
        nonlocal total
        if len(data)>max_output-total: raise ValueError('stream output limit')
        if data:
            written=sink.write(data)
            if written!=len(data): raise OSError('short sink write')
            total+=written
    while True:
        chunk=source.read(chunk_size)
        if not chunk: break
        if not decode:
            emit(engine.compress(chunk)); continue
        if engine.eof: raise ValueError('trailing compressed data')
        while chunk:
            raw=engine.decompress(chunk,min(chunk_size,max_output-total+1))
            emit(raw)
            if engine.unused_data: raise ValueError('trailing compressed data')
            chunk=engine.unconsumed_tail
    if decode:
        if not engine.eof: raise ValueError('truncated compressed stream')
    else: emit(engine.flush())
    return total
