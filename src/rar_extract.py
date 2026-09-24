"""Bounded RAR4/RAR5 extraction in memory. Input is never modified.

Decrypt headers/payloads, construct a private unencrypted stream for the
permissively licensed system libarchive decoder, then verify ORIGINAL file
checksums (including RAR5 keyed checksums) before returning any payload.
No archive-controlled path is ever opened here; host controls publication.
"""
import base64
import ctypes as C
import ctypes.util
import hashlib
import hmac
import struct
import zlib

from rar_crypto import Decryptor, rar4_key, rar5_keys, password_check, checksum_mac, blake2sp

LIMIT = 64 << 20
MAX_MEMBERS = 1000
MAX_HEADER = 2 << 20
RAR4 = b'Rar!\x1a\x07\x00'
RAR5 = b'Rar!\x1a\x07\x01\x00'


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError('truncated RAR input')
        result = self.data[self.pos:self.pos+count]
        self.pos += count
        return result

    def byte(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), 'little')

    def u32(self):
        return int.from_bytes(self.take(4), 'little')

    def vint(self):
        value = 0
        for n in range(10):
            b = self.byte()
            if n == 9 and b > 1:
                raise ValueError('RAR variable integer overflow')
            value |= (b & 127) << (7*n)
            if not b & 128:
                return value
        raise ValueError('unterminated RAR variable integer')


def vint(n):
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    result.append(n)
    return bytes(result)


def block5(kind, flags, body, data=b''):
    header = vint(kind) + vint(flags)
    if flags & 2:
        header += vint(len(data))
    header += body
    header = vint(len(header)) + header
    return struct.pack('<I', zlib.crc32(header)) + header + data


def block4(kind, flags, body, data=b''):
    header = struct.pack('<BHH', kind, flags, 7 + len(body)) + body
    return struct.pack('<H', zlib.crc32(header) & 65535) + header + data


def safe_name(raw, directory=False):
    name = raw.decode('utf-8', 'strict').replace('\\', '/')
    if directory and name.endswith('/'):
        name = name[:-1]
    parts = name.split('/')
    if (not name or len(raw) > 4096 or any(ord(c) < 32 for c in name)
            or any(p in ('', '.', '..') or ':' in p or p.endswith((' ', '.')) for p in parts)):
        raise ValueError('unsafe RAR member path')
    # Also reject Windows devices on Unix, so a manifest is safe to move.
    for p in parts:
        stem = p.split('.')[0].upper()
        if stem in {'CON', 'PRN', 'AUX', 'NUL'} | {f'{s}{n}' for s in ('COM', 'LPT') for n in range(1, 10)}:
            raise ValueError('reserved RAR member path')
    return name


def trim_rar5_padding(data):
    """Walk compressed-block lengths to remove ONLY AES alignment padding."""
    r = Reader(data)
    for _ in range(len(data) // 3 + 1):
        flags, checksum = r.byte(), r.byte()
        width = ((flags >> 3) & 3) + 1
        if width > 3:
            raise ValueError('invalid RAR5 compression block size')
        encoded = r.take(width)
        actual = 0x5a ^ flags
        for byte in encoded:
            actual ^= byte
        if actual != checksum:
            raise ValueError('RAR5 compressed block checksum/password incorrect')
        r.take(int.from_bytes(encoded, 'little'))
        if flags & 0x40:
            if len(data) - r.pos > 15:
                raise ValueError('excess RAR5 ciphertext padding')
            return data[:r.pos]
    raise ValueError('missing final RAR5 compressed block')


class Normalizer:
    def __init__(self, password, decryptor, modern=False):
        self.password, self.decryptor = password, decryptor
        self.modern = modern
        self.members, self.cache = [], {}
        self.total = self.kdf_work = 0
        self.headers_encrypted = False

    def _password(self):
        if self.password is None:
            raise ValueError('RAR password required')
        return self.password

    def key4(self, salt):
        cache_key = (4, salt)
        if cache_key not in self.cache:
            self._cost(1 << 18)
            self.cache[cache_key] = rar4_key(self._password(), salt)
        return self.cache[cache_key]

    def keys5(self, salt, shift):
        if shift > 20:
            raise ValueError('RAR KDF cost exceeds bound')
        cache_key = (5, salt, shift)
        if cache_key not in self.cache:
            self._cost(3 * ((1 << shift) + 32))
            self.cache[cache_key] = rar5_keys(self._password(), salt, shift)
        return self.cache[cache_key]

    def _cost(self, rounds):
        self.kdf_work += rounds
        if self.kdf_work > 16 << 20 or len(self.cache) >= 64:
            raise ValueError('aggregate RAR KDF budget exceeded')

    def add(self, name, size, directory, crc=None, blake=None, hash_key=None):
        self.total += size
        if len(self.members) >= MAX_MEMBERS or self.total > LIMIT or (directory and size):
            raise ValueError('RAR member/output limit exceeded')
        # Include implicit parent directories: reject case aliases, duplicates,
        # and file/directory prefix collisions before invoking a decoder.
        folded = name.casefold()
        for old in self.members:
            other = old['name'].casefold()
            if (folded == other or (folded.startswith(other + '/') and not old['directory'])
                    or (other.startswith(folded + '/') and not directory)):
                raise ValueError('colliding RAR member paths')
            a, b = name.split('/'), old['name'].split('/')
            for x, y in zip(a, b):
                if x.casefold() != y.casefold():
                    break
                if x != y:
                    raise ValueError('case alias in RAR member paths')
        if not directory and crc is None and blake is None:
            raise ValueError('RAR member has no supported integrity checksum')
        self.members.append(dict(name=name, size=size, directory=directory,
                                 crc=crc, blake=blake, hash_key=hash_key))

    def parse5(self, blob):
        stream = Reader(blob[len(RAR5):])
        result = bytearray(RAR5)
        header_key = None
        have_main = ended = False
        for _ in range(4100):
            if header_key is not None:
                iv = stream.take(16)
                first = stream.take(16)
                plain = self.decryptor.decrypt(header_key, iv, first, header=True)
                temp = Reader(plain)
                temp.take(4)
                size = temp.vint() + temp.pos
                if not 7 <= size <= MAX_HEADER:
                    raise ValueError('invalid encrypted RAR5 header size/password')
                encrypted = first + stream.take(((size + 15) & ~15) - 16)
                header = self.decryptor.decrypt(header_key, iv, encrypted, header=True)[:size]
            else:
                start = stream.pos
                stream.take(4)
                length = stream.vint()
                if length > MAX_HEADER or stream.pos - start > 7:
                    raise ValueError('RAR5 header exceeds bound')
                stream.take(length)
                header = stream.data[start:stream.pos]
            r = Reader(header)
            expected = r.u32()
            if zlib.crc32(header[4:]) != expected:
                raise ValueError('RAR5 header CRC mismatch/password incorrect')
            r.vint()
            kind, flags = r.vint(), r.vint()
            if flags & ~0x7f or flags & 0x18:
                raise ValueError('unsupported RAR5 block flags or split volume')
            extra_size = r.vint() if flags & 1 else 0
            data_size = r.vint() if flags & 2 else 0
            if extra_size > len(header) - r.pos or data_size > LIMIT:
                raise ValueError('invalid RAR5 area size')
            extra_start = len(header) - extra_size
            extra = Reader(header[extra_start:])
            body = Reader(header[r.pos:extra_start])
            data = stream.take(data_size)
            if kind == 4:
                if have_main or header_key is not None or self.headers_encrypted or data_size:
                    raise ValueError('misplaced RAR5 encryption header')
                if body.vint() != 0:
                    raise ValueError('unknown RAR encryption version')
                crypt_flags, shift, salt = body.vint(), body.byte(), body.take(16)
                if crypt_flags & ~1:
                    raise ValueError('unknown header encryption flags')
                keys = self.keys5(salt, shift)
                if crypt_flags & 1:
                    password_check(body.take(12), keys[2])
                header_key = keys[0]
                self.headers_encrypted = True
                continue
            if kind == 1:
                archive_flags = body.vint()
                if have_main or archive_flags & 3 or archive_flags & ~31:
                    raise ValueError('duplicate RAR main header or multivolume archive')
                have_main = True
                result += block5(1, 0, vint(archive_flags & 4))
            elif kind == 2:
                if not have_main:
                    raise ValueError('RAR file precedes main header')
                file_flags, size, attrs = body.vint(), body.vint(), body.vint()
                if file_flags & ~7:
                    raise ValueError('unknown RAR file flags/unbounded output')
                if file_flags & 2:
                    body.take(4)
                crc = body.take(4) if file_flags & 4 else None
                comp, host = body.vint(), body.vint()
                name = safe_name(body.take(body.vint()), bool(file_flags & 1))
                directory = bool(file_flags & 1)
                if host not in (0, 1) or (host == 1 and attrs & 0xf000 not in (0, 0x4000, 0x8000)):
                    raise ValueError('unsupported RAR special file')
                method, version, dictionary = (comp >> 7) & 7, comp & 63, (comp >> 10) & 31
                if method > 5 or version > 1 or comp >> 21 or (version == 0 and comp >> 15):
                    raise ValueError('unknown RAR compression method/version')
                if method and (dictionary > 9 or (version == 1 and not comp & (1 << 20) and not self.modern)):
                    raise ValueError('RAR7 new compression or dictionary over 64 MiB is not supported by this decoder')
                if method and version == 1 and comp & (31 << 15) and not self.modern:
                    raise ValueError('RAR7 fractional dictionaries are not supported')
                # Stored modern entries need no dictionary. Version 1 with
                # explicitly legacy algorithm can safely normalize to version 0.
                normalized_comp = (comp if self.modern else (comp & 0x7fc0)) if method else 0
                if method and (128 << 10) * (1 << dictionary) * (32 + ((comp >> 15) & 31)) // 32 > LIMIT:
                    raise ValueError('RAR dictionary exceeds 64 MiB')
                crypt = None
                blake = hash_key = None
                seen = set()
                while extra.pos < len(extra.data):
                    field = Reader(extra.take(extra.vint()))
                    tag = field.vint()
                    if tag in seen:
                        raise ValueError('duplicate RAR5 extra field')
                    seen.add(tag)
                    if tag == 1:
                        if field.vint() != 0:
                            raise ValueError('unsupported RAR5 cipher')
                        cf, shift, salt, iv = field.vint(), field.byte(), field.take(16), field.take(16)
                        if cf & ~3:
                            raise ValueError('unsupported RAR5 encryption flags')
                        keys = self.keys5(salt, shift)
                        if cf & 1:
                            password_check(field.take(12), keys[2])
                        crypt = (keys[0], iv)
                        if cf & 2:
                            hash_key = keys[1]
                    elif tag == 2:
                        if field.vint() != 0:
                            raise ValueError('unsupported RAR5 hash')
                        blake = field.take(32)
                    elif tag in (5, 7):
                        raise ValueError('RAR links, copies and service-data redirection are refused')
                    elif tag not in (3, 4, 6):
                        raise ValueError('unknown RAR5 file extra field')
                self.add(name, size, directory, crc, blake, hash_key)
                if crypt:
                    data = self.decryptor.decrypt(*crypt, data)
                    if method:
                        data = trim_rar5_padding(data)
                if method == 0:
                    if len(data) < size or len(data) - size > (15 if crypt else 0):
                        raise ValueError('invalid stored RAR5 size')
                    data = data[:size]
                body_out = (vint(int(directory)) + vint(size) + vint(attrs) + vint(normalized_comp)
                            + vint(host) + vint(len(name.encode())) + name.encode())
                # The decoder gets no encrypted hash/CRC. Original checksums
                # remain in members and MUST pass after decompression below.
                result += block5(2, 2, body_out, data)
            elif kind == 5:
                if not have_main or body.vint() != 0 or data_size:
                    raise ValueError('RAR continuation/end flags unsupported')
                result += block5(5, 0, vint(0))
                ended = True
                break
            elif kind != 3 and not flags & 4:
                raise ValueError('unknown mandatory RAR5 block')
        if not ended or stream.pos != len(stream.data):
            raise ValueError('missing RAR end marker or trailing data')
        return bytes(result)

    def parse4(self, blob):
        stream = Reader(blob[len(RAR4):])
        result = bytearray(RAR4)
        have_main = ended = False
        for _ in range(4100):
            if self.headers_encrypted:
                key, iv = self.key4(stream.take(8))
                first = stream.take(16)
                plain = self.decryptor.decrypt(key, iv, first, header=True)
                size = int.from_bytes(plain[5:7], 'little')
                if size < 7:
                    raise ValueError('invalid RAR4 header size/password')
                data = first + stream.take(((size + 15) & ~15) - 16)
                header = self.decryptor.decrypt(key, iv, data, header=True)[:size]
            else:
                start = stream.pos
                fixed = stream.take(7)
                size = int.from_bytes(fixed[5:7], 'little')
                stream.take(size - 7)
                header = stream.data[start:stream.pos]
            r = Reader(header)
            crc, kind, flags, size = r.u16(), r.byte(), r.u16(), r.u16()
            if zlib.crc32(header[2:]) & 65535 != crc:
                raise ValueError('RAR4 header CRC mismatch/password incorrect')
            packed = r.u32() if flags & 0x8000 else 0
            if packed > LIMIT:
                raise ValueError('RAR4 packed size exceeds bound')
            if kind == 0x73:
                if have_main or flags & 1:
                    raise ValueError('RAR4 multivolume/duplicate main header')
                have_main = True
                self.headers_encrypted = bool(flags & 0x80)
                result += block4(0x73, flags & 8, b'\0' * 6)
                stream.take(packed)
            elif kind == 0x74:
                if not have_main or flags & 3 or not flags & 0x8000:
                    raise ValueError('RAR4 split file or missing main/data flags')
                unpacked, host, checksum = r.u32(), r.byte(), r.take(4)
                time, version, method, name_len, attrs = r.u32(), r.byte(), r.byte(), r.u16(), r.u32()
                if flags & 0x100:
                    if r.u32() or r.u32():
                        raise ValueError('RAR4 large sizes exceed bound')
                raw_name = r.take(name_len)
                if flags & 0x200:
                    # Unicode names without a NUL are defined as UTF-8; the
                    # proprietary legacy delta-name encoding is not guessed.
                    if b'\0' in raw_name:
                        raise ValueError('RAR4 legacy delta-encoded Unicode name unsupported')
                name = safe_name(raw_name, flags & 0xe0 == 0xe0)
                directory = flags & 0xe0 == 0xe0
                if host > 5 or (host == 3 and attrs & 0xf000 not in (0, 0x4000, 0x8000)):
                    raise ValueError('RAR4 special file unsupported')
                if not 0x30 <= method <= 0x35 or version > 29:
                    raise ValueError('unsupported RAR4 compression version/method')
                crypt = bool(flags & 4)
                if crypt and (not flags & 0x400 or version < 29):
                    raise ValueError('RAR4 non-AES/unsalted encryption unsupported')
                salt = r.take(8) if flags & 0x400 else None
                self.add(name, unpacked, directory, checksum)
                data = stream.take(packed)
                if crypt:
                    data = self.decryptor.decrypt(*self.key4(salt), data)
                if method == 0x30:
                    if len(data) < unpacked or len(data) - unpacked > (15 if crypt else 0):
                        raise ValueError('invalid stored RAR4 size')
                    data = data[:unpacked]
                body = (struct.pack('<IIB', len(data), unpacked, host) + checksum
                        + struct.pack('<IBBHI', time, version, method, len(name.encode()), attrs) + name.encode())
                result += block4(0x74, 0x8000 | (flags & 0xf0), body, data)
            elif kind == 0x7b:
                if not have_main or flags & 1:
                    raise ValueError('RAR4 continuation/end unsupported')
                result += block4(0x7b, 0, b'')
                ended = True
                break
            else:
                stream.take(packed)
        if not ended or stream.pos != len(stream.data):
            raise ValueError('missing RAR4 end marker or trailing data')
        return bytes(result)


def decode_archive(blob, members):
    """libarchive reads only an in-memory sanitized stream, never disk paths."""
    library = ctypes.util.find_library('archive')
    if not library:
        raise ValueError('system libarchive is required for RAR decompression')
    lib = C.CDLL(library)
    P, I, S = C.c_void_p, C.c_int, C.c_size_t
    def bind(name, rest, args):
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = rest, args
        return fn
    new = bind('archive_read_new', P, [])
    free = bind('archive_read_free', I, [P])
    support4 = bind('archive_read_support_format_rar', I, [P])
    support5 = bind('archive_read_support_format_rar5', I, [P])
    open_memory = bind('archive_read_open_memory', I, [P, P, S])
    next_header = bind('archive_read_next_header', I, [P, C.POINTER(P)])
    read = bind('archive_read_data', C.c_ssize_t, [P, P, S])
    pathname = bind('archive_entry_pathname', C.c_char_p, [P])
    filetype = bind('archive_entry_filetype', C.c_uint, [P])
    size = bind('archive_entry_size', C.c_int64, [P])
    version = bind('archive_version_string', C.c_char_p, [])().decode('ascii', 'replace')
    archive = new()
    if not archive:
        raise ValueError('libarchive allocation failed')
    result = []
    try:
        if support4(archive) < 0 or support5(archive) < 0 or open_memory(archive, blob, len(blob)) < 0:
            raise ValueError('libarchive cannot open RAR stream')
        entry = P()
        buffer = C.create_string_buffer(1 << 16)
        for member in members:
            if next_header(archive, C.byref(entry)) != 0:
                raise ValueError('libarchive rejected RAR header')
            path = pathname(entry)
            if not path or path.decode('utf-8').rstrip('/') != member['name'] or size(entry) != member['size']:
                raise ValueError('RAR parser/decoder member disagreement')
            if filetype(entry) not in (0x4000, 0x8000) or (filetype(entry) == 0x4000) != member['directory']:
                raise ValueError('RAR parser/decoder file type disagreement')
            output = bytearray()
            while True:
                count = read(archive, buffer, len(buffer))
                if count < 0:
                    raise ValueError('RAR decompression/checksum failure')
                if count == 0:
                    break
                if len(output) + count > member['size']:
                    raise ValueError('RAR decoder exceeds declared output size')
                output.extend(buffer.raw[:count])
            if len(output) != member['size']:
                raise ValueError('RAR decoded size mismatch')
            result.append(verify_member(member, output))
        if next_header(archive, C.byref(entry)) != 1:
            raise ValueError('unexpected RAR member or missing decoder EOF')
        return result, version
    finally:
        free(archive)


def verify_member(member, output):
    if len(output) != member['size']:
        raise ValueError('RAR decoded size mismatch')
    key = member['hash_key']
    crc = struct.pack('<I', zlib.crc32(output))
    if key:
        crc = checksum_mac(crc, key, is_crc=True)
    if member['crc'] is not None and not hmac.compare_digest(crc, member['crc']):
        raise ValueError('original RAR CRC mismatch/password incorrect')
    if member['blake'] is not None:
        value = blake2sp(output)
        if key:
            value = checksum_mac(value, key)
        if not hmac.compare_digest(value, member['blake']):
            raise ValueError('original RAR BLAKE2sp mismatch/password incorrect')
    return dict(name=member['name'], directory=member['directory'], size=len(output),
                sha256=hashlib.sha256(output).hexdigest(), data_b64=base64.b64encode(output).decode('ascii'))


def decode_tool(blob, members, executable):
    """Explicit operator-installed RAR-compatible `p` decoder. No file extraction.

    Password/key never passed to the tool. Only verified-header, decrypted
    compressed bytes go into a private temporary archive. No source bundled.
    """
    import os
    import subprocess
    import tempfile
    from concurrent.futures import ThreadPoolExecutor
    if not os.path.isabs(executable) or not os.path.isfile(executable):
        raise ValueError('RAR decoder must be an absolute executable file path')
    expected = sum(m['size'] for m in members)
    with tempfile.TemporaryDirectory(prefix='novelrar-decode-') as directory:
        path = os.path.join(directory, 'normalized.rar')
        with open(path, 'xb') as f:
            os.chmod(path, 0o600)
            f.write(blob)
        # -cfg- ignores installed configuration; p streams contents only. No
        # archive names become argv, and stdin is closed (no password prompt).
        process = subprocess.Popen([executable, 'p', '-cfg-', '-inul', '-p-', '--', path],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=directory)
        with ThreadPoolExecutor(max_workers=2) as pool:
            output = pool.submit(process.stdout.read, expected + 1)
            errors = pool.submit(process.stderr.read, 65537)
            try:
                status = process.wait(timeout=90)
            except BaseException:
                process.kill()
                process.wait()
                raise ValueError('RAR decoder exceeded time/resource limit') from None
            finally:
                # Bounded readers can finish before child exit; timeout above
                # terminates a writer blocked after either pipe budget fills.
                if process.poll() is None:
                    process.kill()
                    process.wait()
            raw, stderr = output.result(), errors.result()
        process.stdout.close()
        process.stderr.close()
        if status != 0 or len(raw) != expected or len(stderr) > 65536:
            raise ValueError('external RAR decoder failed or exceeded output limit')
    result = []
    offset = 0
    for member in members:
        size = member['size']
        result.append(verify_member(member, raw[offset:offset+size]))
        offset += size
    return result, 'operator-installed-rar-tool (CPU decompression)'


def extract(blob, password=None, backend='auto', device=0, verify_gpu=False, rar_tool=None):
    if len(blob) > LIMIT:
        raise ValueError('RAR input exceeds 64 MiB')
    if not blob.startswith((RAR4, RAR5)):
        raise ValueError('RAR signature must be at offset zero (SFX unsupported)')
    decryptor = Decryptor(backend, device, verify_gpu)
    try:
        normalizer = Normalizer(password, decryptor, modern=rar_tool is not None)
        normalized = normalizer.parse5(blob) if blob.startswith(RAR5) else normalizer.parse4(blob)
        members, decoder = (decode_tool(normalized, normalizer.members, rar_tool) if rar_tool
                            else decode_archive(normalized, normalizer.members))
        return dict(schema='novelrar.rar-extract', schema_version=1, ok=True,
                    source_sha256=hashlib.sha256(blob).hexdigest(), source_bytes=len(blob),
                    container='rar5' if blob.startswith(RAR5) else 'rar4', members=members,
                    headers_encrypted=normalizer.headers_encrypted, verified=True,
                    output_writes_performed=False, temporary_plaintext_used=rar_tool is not None,
                    external_tools_used=rar_tool is not None, decoder=decoder,
                    acceleration=dict(decryptor.report(), decompression_backend=('operator-rar-tool-cpu' if rar_tool else 'libarchive-cpu')))
    finally:
        decryptor.close()


def main():
    import json
    import sys
    try:
        # Length-delimited options keep passwords off argv/environment/logs.
        line = sys.stdin.buffer.readline(32)
        length = int(line)
        if not 0 <= length <= 8192:
            raise ValueError('RAR options exceed bound')
        options = json.loads(sys.stdin.buffer.read(length))
        blob = sys.stdin.buffer.read(LIMIT + 1)
        report = extract(blob, **options)
        status = 0
    except Exception as exc:
        # Exception messages from dependencies can include input. Return only
        # our explicit validation messages, never tracebacks or passwords.
        message = str(exc) if type(exc) is ValueError else type(exc).__name__
        report = dict(schema='novelrar.rar-extract', ok=False, error=message)
        status = 1
    print(json.dumps(report, ensure_ascii=True))
    return status
