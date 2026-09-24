"""Original OpenCL 1.2 AES-CBC decryption kernel; AMD/NVIDIA GPU devices only.

One independent ciphertext block per work-item; 16-byte vector I/O, private
round state and constant round keys. Bounded 8 MiB reusable device arenas.
No fast-math, vendor-specific binary, password cracking, or claimed speedup.
"""
import ctypes as C
import ctypes.util


def _mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return result


def _sbox():
    result = []
    for byte in range(256):
        inverse = 0 if byte == 0 else 1
        if byte:
            for _ in range(254):
                inverse = _mul(inverse, byte)
        value = inverse ^ 0x63
        for n in range(1, 5):
            value ^= ((inverse << n) | (inverse >> (8 - n))) & 255
        result.append(value)
    return result


SBOX = _sbox()
INV = [SBOX.index(i) for i in range(256)]
KERNEL = r'''
__constant uchar inverse[256] = {INVERSE};
uchar xt(uchar x) { return (uchar)((x << 1) ^ ((x & 128) ? 0x1b : 0)); }
uchar mul(uchar x, uchar y) {
    uchar z=0;
    for (int i=0;i<4;i++) { if (y&1) z^=x; x=xt(x); y>>=1; }
    return z;
}
__kernel void cbc(__global const uchar *src, __global uchar *dst,
                  __constant uchar *keys, __constant uchar *iv,
                  uint rounds, uint blocks) {
    size_t id=get_global_id(0);
    if (id >= blocks) return;
    uchar16 v=vload16(id,src);
    uchar s[16], t[16];
    vstore16(v,0,s);
    for(int j=0;j<16;j++) s[j]^=keys[rounds*16+j];
    for(int r=(int)rounds-1;r>=0;r--) {
        for(int col=0;col<4;col++) for(int row=0;row<4;row++)
            t[col*4+row]=inverse[s[((col-row+4)%4)*4+row]];
        for(int j=0;j<16;j++) t[j]^=keys[r*16+j];
        if(r) for(int c=0;c<16;c+=4) {
            s[c]=mul(t[c],14)^mul(t[c+1],11)^mul(t[c+2],13)^mul(t[c+3],9);
            s[c+1]=mul(t[c],9)^mul(t[c+1],14)^mul(t[c+2],11)^mul(t[c+3],13);
            s[c+2]=mul(t[c],13)^mul(t[c+1],9)^mul(t[c+2],14)^mul(t[c+3],11);
            s[c+3]=mul(t[c],11)^mul(t[c+1],13)^mul(t[c+2],9)^mul(t[c+3],14);
        } else for(int j=0;j<16;j++) s[j]=t[j];
    }
    uchar16 previous;
    if(id) previous=vload16(id-1,src);
    else { uchar p[16]; for(int j=0;j<16;j++) p[j]=iv[j]; previous=vload16(0,p); }
    vstore16(vload16(0,s)^previous,id,dst);
}
'''.replace('INVERSE', ','.join(map(str, INV)))


def expand(key):
    if len(key) not in (16, 32):
        raise ValueError('RAR AES key must be 128 or 256 bits')
    rounds = len(key) // 4 + 6
    result = bytearray(key)
    rcon = 1
    while len(result) < 16 * (rounds + 1):
        word = list(result[-4:])
        if len(result) % len(key) == 0:
            word = [SBOX[x] for x in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _mul(rcon, 2)
        elif len(key) == 32 and len(result) % 32 == 16:
            word = [SBOX[x] for x in word]
        start = len(result) - len(key)
        result.extend(word[i] ^ result[start+i] for i in range(4))
    return bytes(result), rounds


class OpenCLAes:
    CHUNK = 8 << 20

    def __init__(self, device=0, *, _test_cpu=False):
        self.resources = []
        self.description = None
        self.capacity = 0
        self.buffers = []
        name = ctypes.util.find_library('OpenCL')
        if not name:
            name = 'OpenCL.dll' if __import__('os').name == 'nt' else 'libOpenCL.so.1'
        self.lib = C.WinDLL(name) if __import__('os').name == 'nt' else C.CDLL(name)
        P, U, S, Q, I = C.c_void_p, C.c_uint, C.c_size_t, C.c_uint64, C.c_int
        def bind(name, rest, args):
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = rest, args
            setattr(self, name, fn)
        bind('clGetPlatformIDs', I, [U, C.POINTER(P), C.POINTER(U)])
        bind('clGetDeviceIDs', I, [P, Q, U, C.POINTER(P), C.POINTER(U)])
        bind('clGetDeviceInfo', I, [P, U, S, P, C.POINTER(S)])
        bind('clCreateContext', P, [P, U, C.POINTER(P), P, P, C.POINTER(I)])
        bind('clCreateCommandQueue', P, [P, P, Q, C.POINTER(I)])
        bind('clCreateProgramWithSource', P, [P, U, C.POINTER(C.c_char_p), C.POINTER(S), C.POINTER(I)])
        bind('clBuildProgram', I, [P, U, C.POINTER(P), C.c_char_p, P, P])
        bind('clCreateKernel', P, [P, C.c_char_p, C.POINTER(I)])
        bind('clCreateBuffer', P, [P, Q, S, P, C.POINTER(I)])
        bind('clSetKernelArg', I, [P, U, S, P])
        bind('clEnqueueWriteBuffer', I, [P, P, U, S, S, P, U, P, P])
        bind('clEnqueueReadBuffer', I, [P, P, U, S, S, P, U, P, P])
        bind('clEnqueueNDRangeKernel', I, [P, P, U, P, C.POINTER(S), P, U, P, P])
        bind('clFinish', I, [P])
        for kind in ('Context', 'CommandQueue', 'Program', 'Kernel', 'MemObject'):
            bind('clRelease'+kind, I, [P])
        count = U()
        self.check(self.clGetPlatformIDs(0, None, C.byref(count)))
        if count.value > 64:
            raise ValueError('OpenCL platform count exceeds bound')
        platforms = (P * count.value)()
        self.check(self.clGetPlatformIDs(count, platforms, None))
        candidates = []
        for platform in platforms:
            status = self.clGetDeviceIDs(platform, 2 if _test_cpu else 4, 0, None, C.byref(count))
            if status == -1:
                continue
            self.check(status)
            if count.value > 256:
                raise ValueError('OpenCL device count exceeds bound')
            devices = (P * count.value)()
            self.check(self.clGetDeviceIDs(platform, 2 if _test_cpu else 4, count, devices, None))
            for item in devices:
                vendor = U()
                self.check(self.clGetDeviceInfo(item, 0x1001, C.sizeof(vendor), C.byref(vendor), None))
                if _test_cpu or vendor.value in (0x1002, 0x10de):
                    candidates.append(item)
        if device < 0 or device >= len(candidates):
            raise ValueError('no selected AMD/NVIDIA OpenCL GPU device')
        self.device = P(candidates[device])
        info = C.create_string_buffer(4096)
        self.check(self.clGetDeviceInfo(self.device, 0x102b, len(info), info, None))
        self.description = info.value.decode('utf-8', 'replace')
        try:
            err = I()
            self.context = self._own(self.clCreateContext(None, 1, C.byref(self.device), None, None, C.byref(err)), err, 'Context')
            self.queue = self._own(self.clCreateCommandQueue(self.context, self.device, 0, C.byref(err)), err, 'CommandQueue')
            source = C.c_char_p(KERNEL.encode('ascii'))
            self.program = self._own(self.clCreateProgramWithSource(self.context, 1, C.byref(source), None, C.byref(err)), err, 'Program')
            self.check(self.clBuildProgram(self.program, 1, C.byref(self.device), b'-cl-std=CL1.2', None, None))
            self.kernel = self._own(self.clCreateKernel(self.program, b'cbc', C.byref(err)), err, 'Kernel')
            # Independent cryptography/OpenSSL reference; includes chaining and
            # both RAR key sizes before any archive is allowed to use the device.
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            for size in (16, 32):
                key, iv, plain = bytes(range(size)), bytes(range(16)), bytes(range(256)) * 2
                enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                if self.decrypt(key, iv, enc.update(plain) + enc.finalize()) != plain:
                    raise ValueError('OpenCL AES startup self-test failed')
        except Exception:
            self.close()
            raise

    @staticmethod
    def check(status):
        if status != 0:
            raise ValueError('OpenCL operation failed (status %d)' % status)

    def _own(self, pointer, err, kind):
        self.check(err.value)
        if not pointer:
            raise ValueError('OpenCL returned null object')
        self.resources.append((kind, pointer))
        return pointer

    def _arena(self, size):
        if size <= self.capacity:
            return
        for pointer in self.buffers:
            self.clReleaseMemObject(pointer)
        self.buffers = []
        self.capacity = 0
        try:
            for capacity in (size, size, 240, 16):
                err = C.c_int()
                pointer = self.clCreateBuffer(self.context, 1, capacity, None, C.byref(err))
                self.check(err.value)
                if not pointer:
                    raise ValueError('OpenCL allocation returned null')
                self.buffers.append(pointer)
            self.capacity = size
        except Exception:
            self.close()
            raise

    def decrypt(self, key, iv, data):
        if len(iv) != 16 or len(data) % 16:
            raise ValueError('invalid AES-CBC IV or ciphertext size')
        if not data:
            return b''
        schedule, rounds = expand(key)
        self._arena(min(len(data), self.CHUNK))
        src, dst, keys, ivbuf = self.buffers
        self.check(self.clEnqueueWriteBuffer(self.queue, keys, 1, 0, len(schedule), schedule, 0, None, None))
        result = bytearray(len(data))
        for offset in range(0, len(data), self.CHUNK):
            chunk = data[offset:offset+self.CHUNK]
            previous = iv if offset == 0 else data[offset-16:offset]
            self.check(self.clEnqueueWriteBuffer(self.queue, src, 1, 0, len(chunk), chunk, 0, None, None))
            self.check(self.clEnqueueWriteBuffer(self.queue, ivbuf, 1, 0, 16, previous, 0, None, None))
            args = [C.c_void_p(p) for p in (src, dst, keys, ivbuf)] + [C.c_uint(rounds), C.c_uint(len(chunk)//16)]
            for i, value in enumerate(args):
                self.check(self.clSetKernelArg(self.kernel, i, C.sizeof(value), C.byref(value)))
            global_size = C.c_size_t(len(chunk)//16)
            # Runtime selects workgroup size; no assumption about wave32/64.
            self.check(self.clEnqueueNDRangeKernel(self.queue, self.kernel, 1, None, C.byref(global_size), None, 0, None, None))
            output = (C.c_ubyte * len(chunk)).from_buffer(result, offset)
            self.check(self.clEnqueueReadBuffer(self.queue, dst, 1, 0, len(chunk), output, 0, None, None))
        return bytes(result)

    def close(self):
        if getattr(self, 'queue', None):
            self.clFinish(self.queue)
        # Best-effort overwrite before release; Python/driver copies are not
        # guaranteed erased. Never advertise complete secret zeroization.
        if self.buffers and getattr(self, 'queue', None):
            for pointer, size in zip(self.buffers, (self.capacity, self.capacity, 240, 16)):
                self.clEnqueueWriteBuffer(self.queue, pointer, 1, 0, size, bytes(size), 0, None, None)
        for pointer in self.buffers:
            self.clReleaseMemObject(pointer)
        self.buffers = []
        for kind, pointer in reversed(self.resources):
            getattr(self, 'clRelease'+kind)(pointer)
        self.resources = []
        self.queue = None
        self.capacity = 0
