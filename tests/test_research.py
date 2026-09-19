"""Differential, bounds, password, and filesystem regression tests."""
import hashlib
import importlib.util
import io
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import lz4_encode
import lz4_frame
import native_lz4
import research_codec as codec
import safe_output
import unarchive
import rar_store
import rar_reader
import sevenzip
import avccnmp_codec as av
from geex_unpack import inflate_trace

class CodecTests(unittest.TestCase):
    def test_all_streams_roundtrip_and_bound(self):
        for name in codec.CODECS:
            for data in (b'',b'x',b'abc'*5000,bytes(range(256))*10):
                with self.subTest(codec=name,length=len(data)):
                    packed=codec.compress(data,name)
                    self.assertEqual(codec.decompress(packed,name,len(data)),data)
                    if data:
                        with self.assertRaises(ValueError): codec.decompress(packed,name,len(data)-1)
    def test_truncated_and_trailing_streams(self):
        for name in ('deflate','zlib','gzip','bzip2','xz','adaptive'):
            packed=codec.compress(b'hello'*100,name)
            for bad in (packed[:-1],packed+b'x'):
                with self.assertRaises((ValueError,EOFError,zlib.error)):
                    codec.decompress(bad,name)
    def test_adaptive_bounds_and_integrity(self):
        for data in (b'A'*4096,random.Random(4).randbytes(4096)):
            packed=codec.adaptive_compress(data)
            self.assertLessEqual(len(packed),len(data)+codec.HEADER.size)
            damaged=bytearray(packed); damaged[20]^=1
            with self.assertRaises(ValueError): codec.adaptive_decompress(bytes(damaged))
    def test_streaming_with_tiny_chunks(self):
        for name in ('deflate','zlib','gzip'):
            data=b'abcdefgh'*5000
            packed=io.BytesIO()
            codec.transform_stream(io.BytesIO(data),packed,name,chunk_size=7)
            out=io.BytesIO()
            n=codec.transform_stream(io.BytesIO(packed.getvalue()),out,name,decode=True,chunk_size=11)
            self.assertEqual(n,len(data)); self.assertEqual(out.getvalue(),data)
            with self.assertRaises(ValueError):
                codec.transform_stream(io.BytesIO(packed.getvalue()),io.BytesIO(),name,decode=True,max_output=100)
    def test_zip_writing(self):
        for method in ('store','deflate','bzip2','lzma'):
            packed=codec.create_zip({'a/b.txt':b'ABC'*200,'empty':b''},method)
            with zipfile.ZipFile(io.BytesIO(packed)) as arc:
                self.assertEqual(arc.read('a/b.txt'),b'ABC'*200)
    def test_zip_supplied_password(self):
        blob=(ROOT/'tests/fixtures/zip_zipcrypto.zip').read_bytes()
        self.assertEqual(unarchive.open_archive(blob).extracted,0)
        self.assertEqual(unarchive.open_archive(blob,password=b'wrong').extracted,0)
        arch=unarchive.open_archive(blob,password=b'novelrar')
        self.assertEqual(arch.members[0].payload,b'classified payload\n')
        self.assertTrue(arch.members[0].receipt.ok)
    def test_rar_store(self):
        entries={'empty':b'','folder/unicode-\u2603.txt':b'hello'*50}
        archive=unarchive.open_archive(rar_store.create(entries))
        self.assertEqual({m.name:m.payload for m in archive.members},entries)
    def test_rar_writer_with_libarchive_oracle(self):
        import ctypes as C
        import ctypes.util
        library=C.util.find_library('archive')
        if not library: self.skipTest('libarchive oracle unavailable')
        lib=C.CDLL(library)
        lib.archive_read_new.restype=C.c_void_p
        for name in ('archive_read_support_format_all','archive_read_free'):
            getattr(lib,name).argtypes=[C.c_void_p]
        lib.archive_read_open_memory.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t]
        lib.archive_read_next_header.argtypes=[C.c_void_p,C.POINTER(C.c_void_p)]
        lib.archive_entry_pathname.argtypes=[C.c_void_p];lib.archive_entry_pathname.restype=C.c_char_p
        lib.archive_read_data.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t];lib.archive_read_data.restype=C.c_ssize_t
        entries={'empty':b'','a/b':b'hello'*100}
        packed=rar_store.create(entries); buffer=C.create_string_buffer(packed)
        archive=lib.archive_read_new()
        try:
            self.assertEqual(lib.archive_read_support_format_all(archive),0)
            self.assertEqual(lib.archive_read_open_memory(archive,buffer,len(packed)),0)
            actual={}
            while True:
                entry=C.c_void_p();status=lib.archive_read_next_header(archive,C.byref(entry))
                if status==1: break
                self.assertEqual(status,0)
                name=lib.archive_entry_pathname(entry).decode()
                output=C.create_string_buffer(4096)
                n=lib.archive_read_data(archive,output,len(output))
                self.assertGreaterEqual(n,0);actual[name]=output.raw[:n]
            self.assertEqual(actual,entries)
        finally: lib.archive_read_free(archive)

    def test_zero_crc_must_not_be_skipped(self):
        m=rar_reader.RarMember('rar5','a',0,'store',False,False,False,1,1,0,0)
        rar_reader._finish(m,b'a')
        self.assertIsNone(m.payload)
    def test_sevenzip_header_crc(self):
        data=bytearray((ROOT/'tests/fixtures/7z_lzma2.7z').read_bytes()); data[8]^=1
        with self.assertRaises(sevenzip.SevenZError): sevenzip.read(bytes(data))
    def test_av01_strict_lengths(self):
        for data in (b'',b'abc'*100,bytes(range(256))):
            packed=av.compress(data)
            self.assertEqual(av.decompress(packed),data)
            for bad in (packed[:-1],packed+b'garbage'):
                with self.assertRaises((ValueError,IndexError)): av.decompress(bad)
        with self.assertRaises(ValueError): av.compress(b'a',block_size=0)
    def test_deflate_reference_strategies(self):
        for strategy in (zlib.Z_DEFAULT_STRATEGY,zlib.Z_FIXED,zlib.Z_HUFFMAN_ONLY):
            data=b'abcdef'*2000+bytes(range(256))
            enc=zlib.compressobj(6,zlib.DEFLATED,-15,strategy=strategy)
            packed=enc.compress(data)+enc.flush()
            for mode in ('scalar','periodic'):
                self.assertEqual(inflate_trace(packed,match_mode=mode)[0],data)
                with self.assertRaises(ValueError): inflate_trace(packed,len(data)-1,mode)

@unittest.skipUnless(importlib.util.find_spec('cryptography'),'optional cryptography missing')
class CryptoTests(unittest.TestCase):
    def test_authenticated_envelope(self):
        packed=codec.encrypt(b'private data'*30,b'password')
        self.assertEqual(codec.decrypt(packed,b'password'),b'private data'*30)
        self.assertNotEqual(codec.encrypt(b'private data'*30,b'password'),packed)
        with self.assertRaises(ValueError): codec.decrypt(packed,b'wrong')
        for pos in (4,6,22,34,len(packed)-1):
            bad=bytearray(packed);bad[pos]^=1
            with self.assertRaises(ValueError): codec.decrypt(bytes(bad),b'password')
        with self.assertRaises(ValueError): codec.decrypt(packed,b'password',2)

@unittest.skipUnless(importlib.util.find_spec('py7zr'),'optional py7zr missing')
class SevenZipBackendTests(unittest.TestCase):
    def test_headers_password_and_limits(self):
        import optional_sevenzip as backend
        entries={'nested/a':b'xyz'*200,'empty':b''}
        for password in (None,'correct'):
            blob=backend.create(entries,password)
            self.assertEqual(backend.read(blob,password),entries)
            with self.assertRaises(ValueError): backend.read(blob,password,10)
        with self.assertRaises(Exception): backend.read(blob,'incorrect')
        from license_broker import Policy
        with self.assertRaises(ValueError):
            unarchive.open_archive(blob,policy=Policy.strict(),backend='py7zr',password=b'correct')

class OutputTests(unittest.TestCase):
    def test_safe_paths_and_existing_symlinks(self):
        for name in ('../x','/x','C:/x','C:x','a\\..\\b','a:b',''):
            with self.assertRaises(ValueError): safe_output.member_parts(name)
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            Path(root,'link').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(OSError): safe_output.write_member(root,'link/escape',b'bad')
            self.assertFalse(Path(outside,'escape').exists())
            safe_output.write_member(root,'folder/file',b'good')
            self.assertEqual(Path(root,'folder/file').read_bytes(),b'good')
            with self.assertRaises(FileExistsError): safe_output.write_member(root,'folder/file',b'bad')
    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td,'input'); packed=Path(td,'packed'); dst=Path(td,'decoded')
            src.write_bytes(b'hello world'*100)
            for args in (['compress',str(src),'-o',str(packed),'--codec','lz4'],
                         ['decompress',str(packed),'-o',str(dst),'--codec','lz4']):
                subprocess.run([sys.executable,str(ROOT/'src/novelrar_cli.py'),*args],check=True,capture_output=True)
            self.assertEqual(dst.read_bytes(),src.read_bytes())

class LZ4Tests(unittest.TestCase):
    def test_literal_and_match_limits(self):
        with self.assertRaises(ValueError): lz4_frame.decompress_block(b'\x50abcde',4)
        with self.assertRaises(ValueError): lz4_frame.decompress_block(b'\x1fA\x01\x00\xff\x00',10)
        with self.assertRaises(ValueError): lz4_frame.decompress(b'\x50\x2a\x4d\x18')
    @unittest.skipUnless(importlib.util.find_spec('lz4'),'oracle lz4 missing')
    def test_independent_encoder_against_liblz4(self):
        import lz4.block, lz4.frame
        rng=random.Random(184)
        cases=[b'',b'A',b'A'*10000,b'abcd'*4000,bytes(range(256))*300]
        cases += [rng.randbytes(n) for n in (5,12,13,255,65536,70000)]
        for data in cases:
            self.assertEqual(lz4.block.decompress(lz4_encode.compress_block(data),uncompressed_size=len(data)),data)
            frame=lz4_encode.compress(data)
            self.assertEqual(lz4.frame.decompress(frame),data)
            self.assertEqual(lz4_frame.decompress(frame),data)
    @unittest.skipUnless((ROOT/'build/libnovelrar.so').exists(),'native library not built')
    def test_native_overlap_all_distances(self):
        for distance in range(1,257):
            seed=bytes((i*17)%256 for i in range(distance))
            data=(seed*100)[:5000]
            packed=lz4_encode.compress_block(data)
            for mode in native_lz4.MODES:
                self.assertEqual(native_lz4.decompress_block(packed,len(data),mode=mode),data)
                with self.assertRaises(ValueError): native_lz4.decompress_block(packed,len(data)-1,mode=mode)
    @unittest.skipUnless((ROOT/'build/libnovelrar.so').exists(),'native library not built')
    def test_native_prefix_and_malformed(self):
        block=b'\x04\x04\x00\x50TAIL!'
        expected=b'ABCDABCDTAIL!'
        for mode in native_lz4.MODES:
            self.assertEqual(native_lz4.decompress_block(block,len(expected),b'ABCD',mode),expected)
            for bad in (b'',b'\xf0',b'\x10',b'\x10a\x00\x00',b'\x10a\xff\xff'):
                with self.assertRaises(ValueError): native_lz4.decompress_block(bad,100,mode=mode)
    @unittest.skipUnless((ROOT/'build/libnovelrar.so').exists() and importlib.util.find_spec('lz4'),'native/oracle unavailable')
    def test_native_against_oracle_encoder(self):
        import lz4.block
        rng=random.Random(987)
        for i in range(100):
            data=(rng.randbytes(1+i)*70)[:7000]
            packed=lz4.block.compress(data,store_size=False)
            for mode in native_lz4.MODES:
                self.assertEqual(native_lz4.decompress_block(packed,len(data),mode=mode),data)

@unittest.skipUnless((ROOT/'build/libnovelrar.so').exists(),'native library not built')
class DeflateIRTests(unittest.TestCase):
    def test_commands_against_zlib(self):
        import deflate_ir
        rng=random.Random(7)
        for data in (b'',b'a'*65536,b'abc'*1000,rng.randbytes(10000)):
            for strategy in (zlib.Z_DEFAULT_STRATEGY,zlib.Z_FIXED,zlib.Z_HUFFMAN_ONLY):
                enc=zlib.compressobj(6,zlib.DEFLATED,-15,strategy=strategy)
                packed=enc.compress(data)+enc.flush()
                for mode in native_lz4.MODES:
                    self.assertEqual(deflate_ir.decompress(packed,mode=mode),data)
                with self.assertRaises((ValueError,EOFError)): deflate_ir.decompress(packed[:-1])
    def test_invalid_commands(self):
        import deflate_ir
        for commands in ([(0,0,1,5)],[(0,8,0,0)],[(0,1,0,5)],[(0,1,1,99)]):
            with self.assertRaises(ValueError): deflate_ir.execute(b'a',commands,5)

if __name__=='__main__': unittest.main()
