#!/usr/bin/env python3
"""Answer, with evidence, what novelrar can actually decompress.

Runs every fixture through the real pipeline and checks the output byte for
byte against the payload the fixture was built from. Nothing is scored on
"did not raise". Writes results/capability_matrix.md.

    PYTHONPATH=src python3 tests/capability_probe.py
"""
from __future__ import annotations

import os
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(os.environ.get("NOVELRAR_FIXTURES", ROOT / "tests" / "fixtures"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(FIX))

import license_broker as LB   # noqa: E402
import unarchive              # noqa: E402
from _payloads import PAYLOADS, big_text, pseudo_random  # noqa: E402

# What each fixture is supposed to yield. A fixture with no entry here is
# expected to yield nothing (encrypted, or otherwise refused).
EXPECT = {
    "zip_store.zip": PAYLOADS, "zip_deflate.zip": PAYLOADS,
    "zip_datadesc.zip": PAYLOADS,
    "zip_bzip2.zip": {"text.txt": PAYLOADS["text.txt"]},
    "zip_lzma.zip": {"text.txt": PAYLOADS["text.txt"]},
    "7z_copy.7z": PAYLOADS, "7z_lzma1.7z": PAYLOADS, "7z_lzma2.7z": PAYLOADS,
    "7z_bzip2.7z": PAYLOADS, "7z_deflate.7z": PAYLOADS,
    "7z_delta_lzma2.7z": PAYLOADS, "7z_bcj_lzma2.7z": PAYLOADS,
    "rar4_store.rar": PAYLOADS, "rar5_store.rar": PAYLOADS,
    "lz4_text.lz4": {"lz4_text.lz4": PAYLOADS["text.txt"]},
    "lz4_bin.lz4": {"lz4_bin.lz4": PAYLOADS["bin.dat"]},
    "lz4_nochk.lz4": {"lz4_nochk.lz4": PAYLOADS["small.txt"]},
    "lz4_csize.lz4": {"lz4_csize.lz4": PAYLOADS["text.txt"]},
    "lz4_linked.lz4": {"lz4_linked.lz4": PAYLOADS["text.txt"] * 3},
    "lz4_indep.lz4": {"lz4_indep.lz4": PAYLOADS["text.txt"] * 3},
    "lz4_skippable.lz4": {"lz4_skippable.lz4": PAYLOADS["small.txt"]},
    "lz4_legacy.lz4": {"lz4_legacy.lz4": PAYLOADS["text.txt"][:4096]},
    "lz4_linkedbig.lz4": {"lz4_linkedbig.lz4": big_text()},
    "lz4_indepbig.lz4": {"lz4_indepbig.lz4": big_text()},
    "lz4_stored.lz4": {"lz4_stored.lz4": pseudo_random()},
}

FAMILY = OrderedDict([
    ("zip", "ZIP"), ("7z", "7z"), ("rar", "RAR"), ("lz4", "LZ4"),
])


def family_of(fixture: str) -> str:
    for key in FAMILY:
        if fixture.startswith(key):
            return key
    return "other"


def probe_one(fixture: str) -> dict:
    blob = (FIX / fixture).read_bytes()
    arch = unarchive.open_archive(blob, fixture)
    want = EXPECT.get(fixture, {})
    got = {m.name: m.payload for m in arch.members if m.payload is not None}
    exact = sum(1 for n, w in want.items() if got.get(n) == w)
    wrong = [n for n, w in want.items() if n in got and got[n] != w]
    missing = [n for n in want if n not in got]
    unexpected = [n for n in got if n not in want and not any(
        m.is_dir for m in arch.members if m.name == n)]
    lanes = sorted({r.lane for r in arch.receipts}) or ["-"]
    if want:
        verdict = "PASS" if exact == len(want) and not wrong else "FAIL"
    else:
        verdict = "REFUSED" if not got else "FAIL (leaked bytes)"
    return dict(fixture=fixture, family=family_of(fixture),
                container=arch.container, members=len(arch.members),
                exact=exact, want=len(want), verdict=verdict,
                lanes=",".join(lanes), wrong=wrong, missing=missing,
                unexpected=unexpected,
                detail=(arch.members[0].error or "")[:70] if arch.members and not got else "")


def main() -> int:
    rows = [probe_one(p.name) for p in sorted(FIX.iterdir())
            if not p.name.startswith("_")]
    bad = [r for r in rows if r["verdict"].startswith("FAIL")]

    width = max(len(r["fixture"]) for r in rows)
    print(f"{'fixture':<{width}}  {'fmt':<5} {'members':>7} {'exact':>7} "
          f"{'lanes':<20} verdict")
    print("-" * (width + 52))
    for r in rows:
        print(f"{r['fixture']:<{width}}  {r['container']:<5} {r['members']:>7} "
              f"{r['exact']:>3}/{r['want']:<3} {r['lanes']:<20} {r['verdict']}"
              + (f"  {r['detail']}" if r["detail"] else ""))

    # per-family roll-up
    print()
    summary = OrderedDict()
    for key, label in FAMILY.items():
        fam = [r for r in rows if r["family"] == key]
        streams = sum(r["want"] for r in fam)
        okstreams = sum(r["exact"] for r in fam)
        refused = sum(1 for r in fam if r["verdict"] == "REFUSED")
        summary[label] = (len(fam), okstreams, streams, refused)
        print(f"{label:<5} {len(fam):>2} fixtures  {okstreams}/{streams} "
              f"streams bit-exact  {refused} correctly refused")

    receipts = []
    for p in sorted(FIX.iterdir()):
        if not p.name.startswith("_"):
            receipts += unarchive.open_archive(p.read_bytes(), p.name).receipts
    audit = LB.audit(receipts, LB.Policy.strict())
    print()
    print(audit.report())

    out = ROOT / "results" / "capability_matrix.md"
    out.parent.mkdir(exist_ok=True)
    lines = [
        "# Capability matrix",
        "",
        "Generated by `tests/capability_probe.py`. Every `exact` count is a",
        "byte-for-byte comparison against the payload the fixture was built",
        "from; `REFUSED` is the required outcome for encrypted fixtures and",
        "for RAR's compressed stage, not a failure.",
        "",
        "| family | fixtures | streams bit-exact | correctly refused |",
        "|---|--:|--:|--:|",
    ]
    for label, (nf, okc, tot, refused) in summary.items():
        lines.append(f"| {label} | {nf} | {okc}/{tot} | {refused} |")
    lines += ["", "| fixture | container | members | bit-exact | lanes | verdict |",
              "|---|---|--:|--:|---|---|"]
    for r in rows:
        lines.append(f"| `{r['fixture']}` | {r['container']} | {r['members']} | "
                     f"{r['exact']}/{r['want']} | {r['lanes']} | {r['verdict']} |")
    lines += ["", "## Audit", "", "```", audit.report(), "```", ""]
    out.write_text("\n".join(lines))
    print(f"\nwrote {out.relative_to(ROOT)}")

    if bad:
        print(f"\n{len(bad)} fixture(s) FAILED", file=sys.stderr)
        for r in bad:
            print(f"  {r['fixture']}: wrong={r['wrong']} missing={r['missing']}",
                  file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
