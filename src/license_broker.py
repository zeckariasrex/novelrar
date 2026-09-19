#!/usr/bin/env python3
"""Codec provenance broker — the licence boundary as data, not as a README.

The brief was a *novel* way to handle the licensing of proprietary
decompressors, explicitly not a faster or better decompressor. This module is
that answer, and the answer is a reframing: the problem is not that the
algorithms are hard, it is that nobody can cheaply prove which licence each
extracted byte came out under. So make the boundary machine-readable.

Every decode path in this tree is tagged with a **lane**:

  STDLIB     A permissive library already inside CPython. zlib (zlib licence),
             bz2 (BSD), lzma -> liblzma, whose LZMA and branch-filter core
             descends from Igor Pavlov's public-domain LZMA SDK. Nothing is
             vendored; the obligation is already discharged by CPython.
  CLEANROOM  Written in this tree from a published specification that permits
             independent implementation. Each entry cites the document.
  HOST       Delegated to a binary the *operator* installed. We never ship it,
             never link it, never copy from it. The licence obligation sits
             with the operator's own install, and the receipt records exactly
             which binary and version served the bytes.
  REFUSED    No lawful path exists. Encrypted payloads, and RAR's compressed
             LZ/PPM stage, land here and stay here.

Two things fall out of that, and they are the actual deliverable:

 1. **A receipt per extracted stream.** Format, coder chain, lane, licence,
    the citable basis, and how the bytes were verified (CRC-32, xxHash-32).
 2. **An audit gate.** ``audit()`` fails a run whose bytes came out of a lane
    the deployment did not authorise. A shop that cannot accept a HOST
    dependency sets ``Policy.strict()`` and the build breaks loudly at the
    point of extraction, instead of quietly at legal review.

The novelty claim is deliberately modest and is architectural, not
algorithmic: this decompresses nothing faster than the native tools, and is
not trying to. It makes the licence status of a decompression pipeline a
checkable property of a run.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

STDLIB = "STDLIB"
CLEANROOM = "CLEANROOM"
HOST = "HOST"
REFUSED = "REFUSED"

LANE_ORDER = (STDLIB, CLEANROOM, HOST, REFUSED)


@dataclass(frozen=True)
class Capability:
    container: str
    codec: str
    lane: str
    licence: str
    basis: str
    note: str = ""

    @property
    def key(self) -> tuple:
        return (self.container, self.codec)


def _cap(*a, **kw) -> Capability:
    return Capability(*a, **kw)


# ---------------------------------------------------------------------------
# The registry. Every path this repository can take, and why it is allowed.
# ---------------------------------------------------------------------------

CAPABILITIES: dict[tuple, Capability] = {c.key: c for c in (
    # --- ZIP -----------------------------------------------------------
    _cap("zip", "store", CLEANROOM, "n/a (byte copy)",
         "PKWARE APPNOTE.TXT 4.4.5 method 0"),
    _cap("zip", "deflate", STDLIB, "zlib licence",
         "RFC 1951 via CPython zlib",
         "also implemented in-tree as a token-tracing inflater for analysis"),
    _cap("zip", "deflate-trace", CLEANROOM, "n/a (RFC)",
         "RFC 1951 sections 3.2.3-3.2.7",
         "independent inflater; cross-checked byte-for-byte against zlib"),
    _cap("zip", "bzip2", STDLIB, "BSD-4-Clause (bzip2)",
         "APPNOTE method 12 via CPython bz2"),
    _cap("zip", "lzma", STDLIB, "public domain (LZMA SDK) via liblzma",
         "APPNOTE method 14 via CPython lzma"),
    _cap("zip", "zipcrypto", REFUSED, "n/a",
         "APPNOTE 7.0 general-purpose bit 0",
         "encrypted; no password is derived, tried, or accepted"),
    _cap("zip", "aes", REFUSED, "n/a",
         "WinZip AE-1/AE-2, general-purpose bit 6",
         "encrypted; no password is derived, tried, or accepted"),

    # --- 7z ------------------------------------------------------------
    _cap("7z", "container", CLEANROOM, "public domain",
         "7-Zip DOC/7zFormat.txt",
         "fresh header parser; no 7-Zip source vendored"),
    _cap("7z", "copy", CLEANROOM, "n/a (byte copy)", "7zFormat.txt coder 00"),
    _cap("7z", "lzma1", STDLIB, "public domain (LZMA SDK) via liblzma",
         "CPython lzma FORMAT_RAW + FILTER_LZMA1"),
    _cap("7z", "lzma2", STDLIB, "public domain (LZMA SDK) via liblzma",
         "CPython lzma FORMAT_RAW + FILTER_LZMA2"),
    _cap("7z", "delta", CLEANROOM, "n/a (two-line transform)",
         "7zFormat.txt coder 03"),
    _cap("7z", "bcj", STDLIB, "public domain (LZMA SDK) via liblzma",
         "CPython lzma branch filters",
         "liblzma exposes branch filters only inside a raw chain, so the "
         "payload is wrapped in a throwaway LZMA2 layer and unfiltered on the "
         "way out; the filter itself is still liblzma's"),
    _cap("7z", "bcj2", HOST, "public domain (implementable, just not here)",
         "7zFormat.txt coder 0303011B",
         "legal to implement, but nothing in this tree can write BCJ2, so an "
         "implementation could not be tested against an oracle; refused "
         "in-tree and routed to the HOST lane rather than guessed at"),
    _cap("7z", "deflate", STDLIB, "zlib licence", "CPython zlib, coder 040108"),
    _cap("7z", "bzip2", STDLIB, "BSD-4-Clause (bzip2)", "CPython bz2, coder 040202"),
    _cap("7z", "ppmd", HOST, "public domain (LZMA SDK)",
         "7z coder 030401",
         "7-Zip's PPMd var. H; no stdlib equivalent, so not available in-tree"),
    _cap("7z", "zstd", HOST, "BSD-3-Clause (zstd)", "7z coder 04F71101",
         "non-standard 7z coder; zstd is not in CPython's stdlib"),
    _cap("7z", "aes256-sha256", REFUSED, "n/a", "7z coder 06F10701",
         "encrypted; no password is derived, tried, or accepted"),

    # --- LZ4 -----------------------------------------------------------
    _cap("lz4", "block", CLEANROOM, "BSD-2-Clause / CC0 (spec)",
         "lz4/lz4 doc/lz4_Block_format.md",
         "LZ4 carries no proprietary obstacle; the spec invites "
         "independent implementation"),
    _cap("lz4", "frame", CLEANROOM, "BSD-2-Clause / CC0 (spec)",
         "lz4/lz4 doc/lz4_Frame_format.md"),
    _cap("lz4", "xxh32", CLEANROOM, "BSD-2-Clause (spec)",
         "lz4/lz4 doc/xxHash_spec.md",
         "verified against the published test vectors"),

    # --- RAR -----------------------------------------------------------
    _cap("rar", "headers", CLEANROOM, "public documentation",
         "RAR4 technote.txt / RAR5 format notes",
         "metadata only: names, sizes, methods, flags"),
    _cap("rar", "store", CLEANROOM, "n/a (byte copy)",
         "RAR4 method 0x30 / RAR5 method 0"),
    _cap("rar", "compressed", HOST, "operator's own unrar install",
         "unrar licence: sources may be used to read RAR archives, but not "
         "to recreate the RAR compression algorithm, and not to reverse "
         "engineer it",
         "THE licence obstacle in this tree. Not vendored, not translated, "
         "not guessed. Delegated or refused."),
    _cap("rar", "encrypted", REFUSED, "n/a", "RAR4 LHD_PASSWORD / RAR5 extra type 1",
         "encrypted; no password is derived, tried, or accepted"),
    _cap("rar", "header-encrypted", REFUSED, "n/a",
         "RAR4 MHD_PASSWORD / RAR5 header type 4"),
)}


def capability(container: str, codec: str) -> Capability:
    hit = CAPABILITIES.get((container, codec))
    if hit is not None:
        return hit
    return Capability(container, codec, REFUSED, "unknown",
                      "not in the capability registry",
                      "an unregistered codec is refused by default")


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """Which lanes this deployment is willing to accept bytes from."""
    allow: frozenset = frozenset({STDLIB, CLEANROOM, HOST})
    host_binaries: tuple = ("7z", "7za", "7zr", "unrar", "unar", "lz4",
                        "bsdtar", "unzip")
    name: str = "default"

    @classmethod
    def strict(cls) -> "Policy":
        """No external binaries: everything must come from this tree or CPython."""
        return cls(allow=frozenset({STDLIB, CLEANROOM}), host_binaries=(),
                   name="strict-no-host")

    @classmethod
    def permissive(cls) -> "Policy":
        return cls(name="permissive")

    def permits(self, lane: str) -> bool:
        return lane in self.allow


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

@dataclass
class Receipt:
    name: str
    container: str
    codec_chain: str
    lane: str
    licence: str
    basis: str
    n_bytes: int = 0
    verified: str = ""
    ok: bool = False
    detail: str = ""
    tool: str = ""

    def line(self) -> str:
        mark = "ok " if self.ok else "-- "
        size = f"{self.n_bytes:>9}" if self.ok else f"{'':>9}"
        return (f"{mark}{self.lane:<9} {self.container:<5} {self.codec_chain:<22} "
                f"{size}  {self.verified:<12} {self.name}"
                + (f"  [{self.detail}]" if self.detail else ""))


def make_receipt(name: str, container: str, codec: str, *, chain: str = "",
                 n_bytes: int = 0, verified: str = "", ok: bool = False,
                 detail: str = "", tool: str = "") -> Receipt:
    """Build a receipt, taking lane / licence / basis from the registry."""
    cap = capability(container, codec)
    return Receipt(
        name=name, container=container, codec_chain=chain or codec,
        lane=cap.lane, licence=cap.licence, basis=cap.basis,
        n_bytes=n_bytes, verified=verified, ok=ok, detail=detail, tool=tool,
    )


@dataclass
class AuditResult:
    policy: str
    total: int = 0
    extracted: int = 0
    by_lane: dict = field(default_factory=dict)
    violations: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations

    def report(self) -> str:
        head = (f"audit[{self.policy}] {self.extracted}/{self.total} streams "
                f"extracted; lanes " +
                ", ".join(f"{k}={v}" for k, v in sorted(self.by_lane.items())))
        if self.clean:
            return head + "\nPASS: every extracted byte came from an authorised lane."
        lines = [head, f"FAIL: {len(self.violations)} stream(s) outside policy:"]
        lines += [f"  - {v}" for v in self.violations]
        return "\n".join(lines)


def audit(receipts: list, policy: Optional[Policy] = None) -> AuditResult:
    """Fail a run whose bytes came out of a lane the deployment did not allow."""
    policy = policy or Policy()
    res = AuditResult(policy=policy.name, total=len(receipts))
    for r in receipts:
        res.by_lane[r.lane] = res.by_lane.get(r.lane, 0) + 1
        if not r.ok:
            continue
        res.extracted += 1
        if not policy.permits(r.lane):
            res.violations.append(
                f"{r.name}: {r.n_bytes} bytes via lane {r.lane} "
                f"({r.codec_chain}, {r.licence}) — not permitted by "
                f"policy '{policy.name}'")
    return res


# ---------------------------------------------------------------------------
# HOST lane — delegate, never vendor
# ---------------------------------------------------------------------------

@dataclass
class HostTool:
    name: str
    path: str
    version: str


_NOISE = ("caution", "warning", "error", "usage", "note:")


def _probe_version(path: str) -> str:
    """Best-effort version banner, skipping the notices tools print first."""
    for flag in ("--version", "-version", "-V", ""):
        try:
            out = subprocess.run([path] + ([flag] if flag else []),
                                 capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        text = (out.stdout or b"").decode("utf-8", "replace") + "\n" + \
               (out.stderr or b"").decode("utf-8", "replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or any(line.lower().startswith(w) for w in _NOISE):
                continue
            if any(ch.isdigit() for ch in line):
                return line[:80]
    return "version unknown"


def find_host_tool(names, policy: Optional[Policy] = None) -> Optional[HostTool]:
    policy = policy or Policy()
    if not policy.permits(HOST):
        return None
    for n in names:
        if n not in policy.host_binaries:
            continue
        p = shutil.which(n)
        if not p:
            continue
        return HostTool(name=n, path=p, version=_probe_version(p))
    return None


HOST_TOOLS = {
    "rar": ("unrar", "unar", "7z", "bsdtar"),
    "7z": ("7z", "7za", "7zr", "bsdtar"),
    "lz4": ("lz4",),
    "zip": ("unzip", "7z", "bsdtar"),
}


def host_extract(container: str, blob: bytes, member: str,
                 policy: Optional[Policy] = None) -> tuple[Optional[bytes], str, str]:
    """Hand a member to an operator-installed binary.

    Returns (payload, tool-description, detail). The binary is never shipped
    by this project; if the operator has not installed one, this returns
    cleanly with no payload rather than falling back to anything clever.
    """
    policy = policy or Policy()
    if not policy.permits(HOST):
        return None, "", f"policy '{policy.name}' forbids the HOST lane"
    tool = find_host_tool(HOST_TOOLS.get(container, ()), policy)
    if tool is None:
        return None, "", (f"no operator-installed extractor for {container} on PATH "
                          f"(looked for: {', '.join(HOST_TOOLS.get(container, ()))})")
    suffix = {"rar": ".rar", "7z": ".7z", "lz4": ".lz4", "zip": ".zip"}.get(container, ".bin")
    desc = f"{tool.name} {tool.version}".strip()
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / f"archive{suffix}"
        arc.write_bytes(blob)
        dest = Path(td) / "out"
        dest.mkdir()
        if tool.name in ("7z", "7za", "7zr"):
            cmd = [tool.path, "x", "-y", "-p", f"-o{dest}", str(arc), member]
        elif tool.name == "unrar":
            cmd = [tool.path, "x", "-y", "-p-", str(arc), member, str(dest) + "/"]
        elif tool.name == "unar":
            cmd = [tool.path, "-q", "-o", str(dest), str(arc), member]
        elif tool.name == "bsdtar":
            cmd = [tool.path, "-x", "-f", str(arc), "-C", str(dest), member]
        elif tool.name == "unzip":
            cmd = [tool.path, "-qq", "-P", "", str(arc), member, "-d", str(dest)]
        elif tool.name == "lz4":
            cmd = [tool.path, "-d", "-q", str(arc), str(dest / "out.bin")]
        else:
            return None, desc, f"no command template for {tool.name}"
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            return None, desc, f"{type(e).__name__}: {e}"
        hits = [p for p in dest.rglob("*") if p.is_file()]
        exact = [p for p in hits if p.name == Path(member).name]
        pick = (exact or hits or [None])[0]
        if pick is None:
            err = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
            return None, desc, f"rc={proc.returncode} {err[:120]}"
        return pick.read_bytes(), desc, f"rc={proc.returncode}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def capability_table() -> str:
    rows = ["lane       container codec            licence / basis"]
    rows.append("-" * 92)
    for lane in LANE_ORDER:
        for cap in sorted(CAPABILITIES.values(), key=lambda c: (c.container, c.codec)):
            if cap.lane != lane:
                continue
            rows.append(f"{cap.lane:<10} {cap.container:<9} {cap.codec:<16} "
                        f"{cap.licence} — {cap.basis}")
    return "\n".join(rows)


def receipts_table(receipts: list) -> str:
    head = (f"{'':3}{'lane':<9} {'fmt':<5} {'codecs':<22} {'bytes':>9}  "
            f"{'verified':<12} member")
    return "\n".join([head, "-" * 100] + [r.line() for r in receipts])


if __name__ == "__main__":
    print(capability_table())
