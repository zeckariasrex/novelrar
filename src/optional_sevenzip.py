"""Explicit optional py7zr backend: in-memory output, supplied passwords only.
Backend parser/KDF resource behavior remains py7zr's responsibility; use trusted
archives or process isolation for adversarial inputs. No filesystem extraction.
"""
import io
import zlib
from safe_output import member_parts

def create(entries,password=None):
    import py7zr
    out=io.BytesIO()
    with py7zr.SevenZipFile(out,'w',password=password,header_encryption=bool(password)) as arc:
        for name,data in entries.items():
            member_parts(name)
            arc.writestr(data,name)
    return out.getvalue()

def read(blob,password=None,max_output=64<<20):
    import py7zr
    from py7zr.io import Py7zIO, WriterFactory
    if not 0 <= max_output <= 256<<20: raise ValueError('invalid output limit')
    class Sink(Py7zIO):
        def __init__(self,owner): self.buf=io.BytesIO(); self.owner=owner
        def write(self,data):
            if len(data)>self.owner.remaining: raise ValueError('7z aggregate output limit')
            self.owner.remaining-=len(data)
            return self.buf.write(data)
        def read(self,size=None): return self.buf.read(-1 if size is None else size)
        def seek(self,offset,whence=0): return self.buf.seek(offset,whence)
        def flush(self): pass
        def size(self): return len(self.buf.getbuffer())
    class Factory(WriterFactory):
        def __init__(self): self.remaining=max_output; self.products={}
        def create(self,name):
            member_parts(name)
            if name in self.products: raise ValueError('duplicate 7z member')
            sink=Sink(self); self.products[name]=sink; return sink
    factory=Factory()
    with py7zr.SevenZipFile(io.BytesIO(blob),'r',password=password,
                           max_extract_size=max_output) as arc:
        infos=arc.list()
        if sum(x.uncompressed or 0 for x in infos)>max_output:
            raise ValueError('7z declared output exceeds limit')
        for x in infos: member_parts(x.filename)
        if len({x.filename for x in infos})!=len(infos): raise ValueError('duplicate 7z names')
        arc.extractall(factory=factory)
    result={}
    for info in infos:
        if info.is_directory: continue
        sink=factory.products.get(info.filename)
        if sink is None: raise ValueError('7z member was not produced')
        data=sink.buf.getvalue()
        if len(data)!=info.uncompressed: raise ValueError('7z size mismatch')
        if info.crc32 is not None and zlib.crc32(data)&0xffffffff!=info.crc32:
            raise ValueError('7z CRC mismatch')
        result[info.filename]=data
    return result
