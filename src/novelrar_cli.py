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
        arch = unarchive.open_archive(blob, Path(path).name, _policy(args),
                                      password=_password(args), backend=args.backend)
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
        arch = unarchive.open_archive(blob, Path(path).name, _policy(args),
                                      password=_password(args), backend=args.backend)
        pol = _policy(args)
        if not arch.members:
            print("no extractable members: " + "; ".join(arch.notes), file=sys.stderr)
            rc = 1
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
            if m.error or (m.receipt and not m.receipt.ok):
                print(f"  skip {m.name}: verification failed", file=sys.stderr)
                rc = 1
                continue
            from safe_output import write_member
            try:
                write_member(dest,m.name,m.payload,m.is_dir)
            except (ValueError,OSError) as exc:
                print(f"  skip {m.name}: {exc}",file=sys.stderr)
                rc = 1
                continue
            print(f"  wrote {len(m.payload):>9}  {dest / m.name}")
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


def _password(args):
    if not getattr(args,'password',False): return None
    if not hasattr(args,'_password_bytes'):
        import getpass
        args._password_bytes=getpass.getpass('Archive password: ').encode('utf-8')
    return args._password_bytes


def cmd_codec(args):
    import research_codec as codec
    data=Path(args.input).read_bytes()
    if args.cmd == 'compress':
        result=codec.compress(data,args.codec)
    elif args.cmd == 'decompress':
        if args.codec == 'lz4' and args.backend != 'python':
            import lz4_frame
            result=lz4_frame.decompress(data,max_output=args.max_output,backend=args.backend)
        elif args.codec == 'deflate' and args.backend != 'python':
            from deflate_ir import decompress
            result=decompress(data,args.max_output,args.backend)
        else: result=codec.decompress(data,args.codec,args.max_output)
    elif args.cmd == 'encrypt':
        result=codec.encrypt(data,_password(args),args.codec)
    else:
        result=codec.decrypt(data,_password(args),args.max_output)
    with open(args.output,'xb') as stream: stream.write(result)
    print(f'{len(data)} -> {len(result)} bytes')
    return 0


def cmd_create(args):
    import research_codec as codec
    entries={}
    for path in args.files:
        source=Path(path)
        if source.name in entries: raise ValueError('duplicate basename: '+source.name)
        entries[source.name]=source.read_bytes()
    if args.cmd == 'create-rar-store':
        from rar_store import create
        result=create(entries)
    elif args.cmd == 'create-7z':
        if args.strict: raise ValueError('strict policy forbids optional 7z backend')
        from optional_sevenzip import create
        pw=_password(args)
        result=create(entries,pw.decode('utf-8') if pw is not None else None)
    else: result=codec.create_zip(entries,args.codec)
    with open(args.output,'xb') as stream: stream.write(result)
    return 0


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
    p.add_argument("--password", action="store_true", help="prompt for ZIP/7z password")
    p.add_argument("--backend",choices=("builtin","py7zr"),default="builtin")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("extract", help="extract members a policy permits")
    p.add_argument("archives", nargs="+")
    p.add_argument("-d", "--dest", default="out")
    p.add_argument("--password", action="store_true", help="prompt for ZIP/7z password")
    p.add_argument("--backend",choices=("builtin","py7zr"),default="builtin")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("audit", help="fail if bytes came from a barred lane")
    p.add_argument("archives", nargs="+")
    p.set_defaults(func=cmd_audit)

    from research_codec import CODECS, DEFAULT_LIMIT
    for command in ('compress','decompress','encrypt','decrypt'):
        p=sub.add_parser(command)
        p.add_argument('input')
        p.add_argument('-o','--output',required=True)
        p.add_argument('--codec',choices=CODECS,default='adaptive')
        p.add_argument('--max-output',type=int,default=DEFAULT_LIMIT)
        p.add_argument('--backend',choices=('python','scalar','grow','sse2','asm'),default='python')
        p.set_defaults(func=cmd_codec,password=command in ('encrypt','decrypt'))
    for command in ('create-zip','create-7z','create-rar-store'):
        p=sub.add_parser(command)
        p.add_argument('files',nargs='+')
        p.add_argument('-o','--output',required=True)
        p.add_argument('--codec',choices=('store','deflate','bzip2','lzma'),default='deflate')
        if command == 'create-7z': p.add_argument('--password',action='store_true')
        p.set_defaults(func=cmd_create)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
