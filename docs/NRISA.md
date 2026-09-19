# NRISA — Novel Reconstruction Instruction Set Algebra

Owned format. Magic `NRIS`. This is not a RAR, ZIP, LZ4, or DEFLATE decoder.
It does not read WinRAR payloads. It is an original reconstruction grammar
over the ring $\mathbb{Z}/256\mathbb{Z}$, executed with ordinary x86 byte ops.

## State

Tape $T \in (\mathbb{Z}/256\mathbb{Z})^{C}$ and write cursor $w$. Commands only
append. A command with distance $d$ reads $T[w+i-d]$ and requires $d \le w$.

## Commands

| tag | name | effect |
|---:|---|---|
| 0 | EMIT $\ell$ | $T[w+i] \leftarrow b_i$ for given bytes $b$ |
| 1 | COPY $d,\ell$ | $T[w+i] \leftarrow T[w+i-d]$ |
| 2 | FILL $\ell,v$ | $T[w+i] \leftarrow v$ |
| 3 | AXPY $d,\ell,a,b$ | $T[w+i] \leftarrow a\cdot T[w+i-d] + b$ |

Arithmetic is mod 256. COPY may overlap ($d < \ell$); each new byte is the
next source. AXPY length is capped at $d$ so the source span is already written.
Zero length and $d=0$ are rejected for COPY/FILL/AXPY.

## Solving AXPY

Given source $S$ and dest $D$ of length $\ell$, find $a,b$ such that
$D[k] \equiv a S[k] + b \pmod{256}$ for every $k$.

From two indices $i,j$:

$$a\cdot\Delta S \equiv \Delta D \pmod{256},\quad
\Delta S = S[i]-S[j],\ \Delta D = D[i]-D[j].$$

Solvable iff $\gcd(\Delta S, 256)$ divides $\Delta D$. When several $a$
exist the encoder tests each residue class against the whole span and keeps
the first that fits. Prefer FILL when $a=0$, COPY when $a=1$ and $b=0$.
Those are not emitted as AXPY.

Identities used by the ISA mapper:

- $a=1$: $D = S + b$ — `PADDB` with broadcast $b$
- $a=255$: $D = b - S$ — `PSUBB` from broadcast $b$. Equivalent:
  $(S \oplus 0xFF) + (b+1)$ (`PXOR` then `PADDB`). `NOT(S)+b` is wrong by one.
- $a=0$: FILL $b$
- other $a$: scalar, because SSE2 has no 8-bit multiply

If $d < 16$, AXPY steps one byte. A 16-byte load of $T[w-d:w-d+16]$
would miss the serial dependence $T[w]$ feeds $T[w+d]$.

## Wire (little-endian)

```
magic[4]=NRIS  ver:u8=1  flags:u8  usize:u32  ncmd:u32
```

`flags bit 0`: a SHA-256 of the plaintext follows the command list.

```
EMIT  u8=0  u16 n  n bytes
COPY  u8=1  u16 n  u16 dist
FILL  u8=2  u16 n  u8 v
AXPY  u8=3  u16 n  u16 dist  u8 a  u8 b
```

Reject truncated input, trailing bytes, size mismatch, unknown tags,
and digest failure.

## ISA mapping

| command | scalar | grow / SSE2 / `rep movsb` |
|---|---|---|
| EMIT | `memcpy` | same |
| COPY | byte loop | `nr_expand` modes 1/2/3 |
| FILL | store loop | `memset` |
| AXPY $a=1$, $d\ge 16$ | byte add | `PADDB` |
| AXPY $a=255$, $d\ge 16$ | byte sub | `PSUBB` |
| AXPY other | byte `a*src+b` | same |

## What this is not

Not a claim of universal compression. Header plus digest is 46 bytes before
any command; tiny inputs grow. Not a RAR bitstream. Not a password scheme.
Measured Python prototype (header + digest included): repeat200 200→50,
period3 240→57, ramp512 512→97, text450 450→99, affine-add 128→85.
