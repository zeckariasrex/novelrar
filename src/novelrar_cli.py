#!/usr/bin/env python3
"""novelrar command line: list, extract, audit, and show the licence lanes.

    PYTHONPATH=src python3 src/novelrar_cli.py capabilities
    PYTHONPATH=src python3 src/novelrar_cli.py list    ARCHIVE...
    PYTHONPATH=src python3 src/novelrar_cli.py extract ARCHIVE -d OUTDIR
    PYTHONPATH=src python3 src/novelrar_cli.py audit   ARCHIVE... --strict

``audit`` exits non-zero when any extracted byte came out of a lane the
policy does not permit, so it drops straight into CI.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import license_broker as LB
import unarchive
from license_broker import Policy


def _policy(args) -> Policy:
    return Policy.strict() if args.strict else Policy()


def cmd_capabilities(args) -> int:
    print(LB.capability_table())
    print()
    print("host tools visible on PATH:")
    pol = _policy(args)
    for container, names in sorted(LB.HOST_TOOLS.items()):
        tool = LB.find_host_tool(names, pol)
        print(f"  {container:<5} " + (f"{tool.name} — {tool.version}" if tool
                                      else f"none of {', '.join(names)}"))
    return 0


def cmd_list(args) -> int:
    for path in args.archives:
        blob = Path(path).read_bytes()
        arch = unarchive.open_archive(blob, Path(path).name, _policy(args))
        print(f"\n=== {path}  [{arch.container}]  "
              f"{arch.extracted}/{len(arch.members)} extracted")
        for note in arch.notes[:args.notes]:
            print(f"    . {note}")
        if arch.receipts:
            print(LB.receipts_table(arch.receipts))
    return 0


def cmd_extract(args) -> int:
    dest = Path(args.dest)
    rc = 0
    for path in args.archives:
        blob = Path(path).read_bytes()
        arch = unarchive.open_archive(blob, Path(path).name, _policy(args))
        pol = _policy(args)
        for m in arch.members:
            if m.payload is None:
                print(f"  skip {m.name}: {m.error}", file=sys.stderr)
                rc = 1
                continue
            if m.receipt and not pol.permits(m.receipt.lane):
                print(f"  skip {m.name}: lane {m.receipt.lane} not permitted",
                      file=sys.stderr)
                rc = 1
                continue
            # keep members inside dest: reject absolute paths and .. traversal
            rel = Path(m.name.replace("\\", "/"))
            if rel.is_absolute() or ".." in rel.parts:
                print(f"  skip {m.name}: unsafe member path", file=sys.stderr)
                rc = 1
                continue
            out = dest / rel
            if m.is_dir:
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(m.payload)
            print(f"  {m.receipt.lane:<9} {len(m.payload):>9}  {out}")
    return rc


def cmd_audit(args) -> int:
    pol = _policy(args)
    receipts = []
    for path in args.archives:
        blob = Path(path).read_bytes()
        arch = unarchive.open_archive(blob, Path(path).name, pol)
        receipts += arch.receipts
    result = LB.audit(receipts, pol)
    print(result.report())
    return 0 if result.clean else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="novelrar", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action="store_true",
                    help="forbid the HOST lane: nothing may come from an "
                         "external binary")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("capabilities", help="print the licence-lane registry")
    p.set_defaults(func=cmd_capabilities)

    p = sub.add_parser("list", help="list members with a receipt each")
    p.add_argument("archives", nargs="+")
    p.add_argument("--notes", type=int, default=6, help="container notes to show")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("extract", help="extract members a policy permits")
    p.add_argument("archives", nargs="+")
    p.add_argument("-d", "--dest", default="out")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("audit", help="fail if bytes came from a barred lane")
    p.add_argument("archives", nargs="+")
    p.set_defaults(func=cmd_audit)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
