"""Root-relative extraction using directory descriptors and no-follow opens.
POSIX only: unsupported platforms fail closed rather than using a racy fallback.
"""
import os
from pathlib import PurePosixPath, PureWindowsPath

def member_parts(name):
    name = name.replace('\\','/')
    path=PurePosixPath(name)
    if ('\x00' in name or path.is_absolute() or PureWindowsPath(name).drive
            or '..' in path.parts or not path.parts or ':' in name):
        raise ValueError('unsafe member path')
    return path.parts

def write_member(root,name,payload,is_dir=False):
    parts=member_parts(name)
    if not hasattr(os,'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise OSError('safe extraction requires POSIX no-follow directory operations')
    os.makedirs(root,exist_ok=True)
    flags=os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd=os.open(root,flags)
    try:
        for part in parts if is_dir else parts[:-1]:
            try: os.mkdir(part,dir_fd=fd)
            except FileExistsError: pass
            nxt=os.open(part,flags,dir_fd=fd)
            os.close(fd); fd=nxt
        if not is_dir:
            # Exclusive creation also refuses existing files, hardlinks and symlinks.
            target=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                           0o600,dir_fd=fd)
            try:
                with os.fdopen(target,'wb') as stream: stream.write(payload)
            except BaseException:
                os.unlink(parts[-1],dir_fd=fd)
                raise
    finally: os.close(fd)
