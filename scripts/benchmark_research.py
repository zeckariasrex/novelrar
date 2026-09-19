#!/usr/bin/env python3
"""Reproducible microbenchmarks, including Python/FFI/allocation overhead.
Not a general performance claim. Native tests require explicit build first.
"""
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import lz4.block
import lz4_encode,lz4_frame,native_lz4,research_codec
from geex_unpack import inflate_trace
import zlib
import deflate_ir

def measure(fn,expected,iterations=20):
    assert fn()==expected
    samples=[]
    for _ in range(5):
        start=time.perf_counter_ns()
        for _ in range(iterations): assert fn()==expected
        samples.append((time.perf_counter_ns()-start)/iterations/1e9)
    seconds=statistics.median(samples)
    return {'seconds':seconds,'MiB_per_second':len(expected)/(1<<20)/seconds}

def main():
    rng=random.Random(912)
    cases={'repeat1':b'A'*65536,'period3':(b'abc'*21846)[:65536],
           'text':(b'Independent machine-level archive research. '*1600)[:65536],
           'ramp':bytes(range(256))*256,'random':rng.randbytes(65536)}
    result={'environment':{'platform':platform.platform(),'python':sys.version,
                          'compiler':subprocess.check_output(['cc','--version'],text=True).splitlines()[0]},
            'methodology':'5 samples, median; 20 decodes each (DEFLATE tracer: 2); includes FFI, allocations and equality checks',
            'lz4':{},'compression':{},'deflate':{}}
    for name,data in cases.items():
        packed=lz4.block.compress(data,store_size=False)
        variants={'python-periodic':lambda:lz4_frame.decompress_block(packed,len(data)),
                  'liblz4-oracle':lambda:lz4.block.decompress(packed,uncompressed_size=len(data))}
        for mode in native_lz4.MODES:
            variants[mode]=lambda m=mode:native_lz4.decompress_block(packed,len(data),mode=m)
        result['lz4'][name]={key:measure(fn,data) for key,fn in variants.items()}
        result['compression'][name]={}
        for codec in research_codec.CODECS:
            start=time.perf_counter_ns(); encoded=research_codec.compress(data,codec)
            elapsed=(time.perf_counter_ns()-start)/1e9
            assert research_codec.decompress(encoded,codec)==data
            result['compression'][name][codec]={'bytes':len(encoded),'ratio':len(encoded)/len(data),'encode_seconds':elapsed}
        enc=zlib.compressobj(6,zlib.DEFLATED,-15); raw=enc.compress(data)+enc.flush()
        result['deflate'][name]={mode:measure(lambda m=mode:inflate_trace(raw,match_mode=m)[0],data,2)
                                  for mode in ('scalar','periodic')}
        result['deflate'][name]['native-ir-grow']=measure(lambda:deflate_ir.decompress(raw),data,2)
        result['deflate'][name]['zlib']=measure(lambda:zlib.decompress(raw,-15),data,20)
    target=ROOT/'results/native_research_benchmark.json'
    target.write_text(json.dumps(result,indent=2)+'\n')
    print(target)
if __name__=='__main__': main()
