def big_text() -> bytes:
    """The multi-block LZ4 payload, recomputed rather than committed."""
    return (b"The quick brown fox jumps over the lazy dog. "
            b"NOVELRAR windmill paint. ") * 3000


def pseudo_random(n: int = 70000) -> bytes:
    """Incompressible bytes, deterministic so fixtures stay stable.

    A counter through SHA-256: reproducible without shipping the blob, and
    genuinely unmatchable, so LZ4 is forced to emit *stored* blocks.
    """
    import hashlib
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"novelrar" + i.to_bytes(8, "little")).digest()
        i += 1
    return bytes(out[:n])


TEXT = (b"The quick brown fox jumps over the lazy dog. "
        b"Pack my box with five dozen liquor jugs. "
        b"Geometry evaluates shadow, shape, and surface. ") * 40
BIN = bytes((i * 37 + (i >> 3)) & 0xFF for i in range(4096))
SMALL = b"hello novelrar\n"

PAYLOADS = {"text.txt": TEXT, "bin.dat": BIN, "small.txt": SMALL}


