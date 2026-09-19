"""HOST extractor handoff: supplied password only, isolated subprocess.

No password search. No in-tree RAR codec. The operator-installed binary
does the compressed/encrypted work. Isolation is best-effort unshare/rlimits.
Passwords are argv elements for the child; they are never written to receipts.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import license_broker as LB
from safe_output import member_parts


def _password_text(password) -> str:
    if password is None:
        return ''
    if isinstance(password, bytes):
        return password.decode('utf-8', 'surrogateescape')
    return str(password)


def host_command(tool_name: str, tool_path: str, archive: str, dest: str,
                 member: Optional[str] = None, password=None) -> list[str]:
    """Build argv. Password is a single argument; never interpolated into flags."""
    pw = _password_text(password)
    dest = str(dest)
    archive = str(archive)
    if tool_name in ('7z', '7za', '7zr'):
        cmd = [tool_path, 'x', '-y', '-p' + pw, '-o' + dest, archive]
        if member:
            cmd.append(member)
        return cmd
    if tool_name == 'unrar':
        cmd = [tool_path, 'x', '-y', '-p' + (pw if pw else '-'), archive]
        if member:
            cmd.append(member)
        cmd.append(dest.rstrip('/') + '/')
        return cmd
    if tool_name == 'unar':
        cmd = [tool_path, '-q', '-o', dest]
        if pw:
            cmd.extend(['-p', pw])
        cmd.append(archive)
        if member:
            cmd.append(member)
        return cmd
    if tool_name == 'bsdtar':
        cmd = [tool_path, '-x', '-f', archive, '-C', dest]
        if pw:
            cmd.extend(['--passphrase', pw])
        if member:
            cmd.append(member)
        return cmd
    if tool_name == 'unzip':
        cmd = [tool_path, '-qq', '-P', pw, archive]
        if member:
            cmd.append(member)
        cmd.extend(['-d', dest])
        return cmd
    if tool_name == 'lz4':
        return [tool_path, '-d', '-q', archive, str(Path(dest) / 'out.bin')]
    raise ValueError(f'no command template for {tool_name}')


def _walk_files(root: Path) -> dict[str, bytes]:
    out = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if path.stat().st_size > 64 << 20:
            raise ValueError(f'host output exceeds 64 MiB limit: {rel}')
        out[rel] = path.read_bytes()
    return out


def _run(cmd: list[str], desc: str):
    try:
        from host_isolate import run as isolated_run
        proc = isolated_run(cmd, timeout=120)
        desc = f'{desc} [isolated]'
    except (OSError, Exception) as exc:
        return None, desc, f'{type(exc).__name__}: {exc}'
    if proc.returncode != 0:
        return None, desc, f'extractor failed: rc={proc.returncode}'
    return proc, desc, 'rc=0'


def extract(container: str, blob: bytes, member: str,
            policy: Optional[LB.Policy] = None, password=None):
    """Extract one member through an operator-installed binary."""
    policy = policy or LB.Policy()
    if not policy.permits(LB.HOST):
        return None, '', f"policy '{policy.name}' forbids the HOST lane"
    try:
        parts = member_parts(member)
    except ValueError as exc:
        return None, '', str(exc)
    if any(c in member for c in '*?[]') or any(p.startswith('-') for p in parts):
        return None, '', 'ambiguous host member selector'
    tool = LB.find_host_tool(LB.HOST_TOOLS.get(container, ()), policy)
    if tool is None:
        looked = ', '.join(LB.HOST_TOOLS.get(container, ()))
        return None, '', f'no operator-installed extractor for {container} on PATH (looked for: {looked})'
    suffix = {'rar': '.rar', '7z': '.7z', 'lz4': '.lz4', 'zip': '.zip'}.get(container, '.bin')
    desc = f'{tool.name} {tool.version}'.strip()
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / f'archive{suffix}'
        arc.write_bytes(blob)
        dest = Path(td) / 'out'
        dest.mkdir()
        try:
            cmd = host_command(tool.name, tool.path, str(arc), str(dest), member, password)
        except ValueError as exc:
            return None, desc, str(exc)
        proc, desc, detail = _run(cmd, desc)
        if proc is None:
            return None, desc, detail
        current = dest
        for part in parts:
            current = current / part
            if current.is_symlink():
                return None, desc, 'extractor returned symlink'
        pick = dest.joinpath(*parts)
        if not pick.is_file():
            files = _walk_files(dest)
            if len(files) == 1:
                pick = dest / next(iter(files))
            else:
                return None, desc, 'exact requested member not produced'
        if pick.stat().st_size > 64 << 20:
            return None, desc, 'host output exceeds 64 MiB limit'
        return pick.read_bytes(), desc, 'rc=0'


def extract_all(container: str, blob: bytes,
                policy: Optional[LB.Policy] = None, password=None):
    """Extract every regular file. Used when headers hide member names."""
    policy = policy or LB.Policy()
    if not policy.permits(LB.HOST):
        return None, '', f"policy '{policy.name}' forbids the HOST lane"
    tool = LB.find_host_tool(LB.HOST_TOOLS.get(container, ()), policy)
    if tool is None:
        looked = ', '.join(LB.HOST_TOOLS.get(container, ()))
        return None, '', f'no operator-installed extractor for {container} on PATH (looked for: {looked})'
    suffix = {'rar': '.rar', '7z': '.7z', 'lz4': '.lz4', 'zip': '.zip'}.get(container, '.bin')
    desc = f'{tool.name} {tool.version}'.strip()
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / f'archive{suffix}'
        arc.write_bytes(blob)
        dest = Path(td) / 'out'
        dest.mkdir()
        try:
            cmd = host_command(tool.name, tool.path, str(arc), str(dest), None, password)
        except ValueError as exc:
            return None, desc, str(exc)
        proc, desc, detail = _run(cmd, desc)
        if proc is None:
            return None, desc, detail
        try:
            files = _walk_files(dest)
        except ValueError as exc:
            return None, desc, str(exc)
        if not files:
            return None, desc, 'host produced no files'
        return files, desc, 'rc=0'
