"""RAR supplied-password crypto; no password search or external processes.

KDF conventions: RARLAB RAR5 technical note; Marko Kreen's ISC-licensed
rarfile crypto documentation. See docs/RAR-ACCELERATION.md for provenance.
"""
import hashlib
import hmac
import struct


def rar4_key(password, salt):
    seed = password.encode('utf-16le')
    # Older RAR SHA-1 mutates long input buffers. Do not silently derive a
    # standard SHA-1 key for that incompatible case.
    if len(seed) > 56 or len(salt) != 8:
        raise ValueError('RAR4 supports at most 28 UTF-16 password units and an 8-byte salt')
    seed += salt
    state = hashlib.sha1()
    iv = bytearray(16)
    for counter in range(1 << 18):
        state.update(seed)
        state.update(counter.to_bytes(3, 'little'))
        if counter % (1 << 14) == 0:
            iv[counter >> 14] = state.copy().digest()[19]
    key = b''.join(state.digest()[i:i+4][::-1] for i in range(0, 16, 4))
    return key, bytes(iv)


def rar5_keys(password, salt, shift):
    if len(password.encode('utf-16le')) > 254 or len(salt) != 16 or not 0 <= shift <= 20:
        raise ValueError('RAR5 password, salt or KDF cost exceeds supported bounds')
    password = password.encode('utf-8')
    rounds = 1 << shift
    # Three cumulative PBKDF2 results, NOT three output blocks.
    return tuple(hashlib.pbkdf2_hmac('sha256', password, salt, rounds + n, 32)
                 for n in (0, 16, 32))


def fold(data, width):
    result = bytearray(width)
    for i, value in enumerate(data):
        result[i % width] ^= value
    return bytes(result)


def password_check(check, key_check):
    if len(check) != 12 or not hmac.compare_digest(hashlib.sha256(check[:8]).digest()[:4], check[8:]):
        raise ValueError('damaged RAR5 password check')
    if not hmac.compare_digest(fold(key_check, 8), check[:8]):
        raise ValueError('incorrect RAR password')


def checksum_mac(raw, hash_key, is_crc=False):
    digest = hmac.digest(hash_key, raw, 'sha256')
    return fold(digest, 4) if is_crc else digest


def blake2sp(data):
    # BLAKE2 parallel tree parameters, 8 leaves / 64-byte stripes.
    leaves = [hashlib.blake2s(digest_size=32, fanout=8, depth=2, leaf_size=0,
              node_offset=i, node_depth=0, inner_size=32, last_node=(i == 7))
              for i in range(8)]
    for offset in range(0, len(data), 64):
        leaves[(offset // 64) % 8].update(data[offset:offset+64])
    root = hashlib.blake2s(digest_size=32, fanout=8, depth=2, leaf_size=0,
                          node_offset=0, node_depth=1, inner_size=32, last_node=True)
    root.update(b''.join(leaf.digest() for leaf in leaves))
    return root.digest()


def cpu_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError('unaligned RAR ciphertext')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


class Decryptor:
    """A per-job device context. Explicit GPU mode never silently falls back."""
    def __init__(self, backend='auto', device=0, verify_gpu=False):
        if backend not in ('auto', 'cpu', 'gpu') or device < 0:
            raise ValueError('invalid RAR crypto backend/device')
        self.backend, self.device, self.verify_gpu = backend, device, verify_gpu
        self.gpu = None
        self.gpu_error = None
        self.gpu_bytes = self.cpu_bytes = 0
        if backend == 'gpu':
            self._open_gpu()

    def _open_gpu(self):
        if self.gpu is None and self.gpu_error is None:
            try:
                from rar_opencl import OpenCLAes
                self.gpu = OpenCLAes(self.device)
            except (OSError, ValueError) as exc:
                self.gpu_error = str(exc)
        if self.gpu is None and self.backend == 'gpu':
            raise ValueError('requested RAR GPU unavailable: ' + self.gpu_error)

    def decrypt(self, key, iv, data, header=False):
        if not header and self.backend != 'cpu' and (self.backend == 'gpu' or len(data) >= 256 << 10):
            self._open_gpu()
            if self.gpu:
                # A failed GPU invocation is fatal, even in auto. Never hide a
                # driver/kernel failure by publishing a CPU result as GPU work.
                result = self.gpu.decrypt(key, iv, data)
                if self.verify_gpu and not hmac.compare_digest(result, cpu_decrypt(key, iv, data)):
                    raise ValueError('GPU/CPU AES disagreement')
                self.gpu_bytes += len(data)
                return result
        self.cpu_bytes += len(data)
        return cpu_decrypt(key, iv, data)

    def report(self):
        return dict(requested=self.backend, gpu_bytes=self.gpu_bytes, cpu_bytes=self.cpu_bytes,
                    gpu_device=self.gpu.description if self.gpu else None,
                    fallback_reason=self.gpu_error, gpu_full_cross_check=self.verify_gpu,
                    kdf_backend='hashlib-cpu', cpu_aes_backend='cryptography-provider-runtime-dispatch',
                    decompression_backend='libarchive-cpu')

    def close(self):
        if self.gpu:
            self.gpu.close()
            self.gpu = None
