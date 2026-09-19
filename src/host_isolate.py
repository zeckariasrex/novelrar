"""Best-effort HOST process isolation. Not a security sandbox.

Tries Linux user/network/ipc/uts namespaces plus resource limits and a new
session. Each combination is attempted independently; absence of unshare or
a rejected unprivileged namespace is not a hard failure. Limits apply to
the child only when preexec_fn runs. This is a substitute for a real
sandbox, not an equivalent.
"""
from __future__ import annotations

import os
import resource
import shutil
import subprocess
from typing import Optional, Sequence

# CPU seconds, address space, file size, open files, core.
_LIMITS = (
    (resource.RLIMIT_CPU, (20, 20)),
    (resource.RLIMIT_FSIZE, (64 << 20, 64 << 20)),
    (resource.RLIMIT_NOFILE, (64, 64)),
    (resource.RLIMIT_CORE, (0, 0)),
)
try:
    _LIMITS += ((resource.RLIMIT_AS, (512 << 20, 512 << 20)),)
except AttributeError:
    pass


def _apply_limits_and_session():
    for which, val in _LIMITS:
        try:
            resource.setrlimit(which, val)
        except (ValueError, OSError):
            pass
    os.setsid()


def wrap(cmd: Sequence[str], isolated: bool = True) -> list[str]:
    """Prefix an argv with unshare when isolation is requested and available."""
    cmd = [str(x) for x in cmd]
    if not isolated:
        return cmd
    unshare = shutil.which('unshare')
    if not unshare:
        return cmd
    return [unshare, '--user', '--net', '--ipc', '--uts', '--', *cmd]


def run(cmd: Sequence[str], *, isolated: bool = True, timeout: int = 120,
        cwd: Optional[str] = None, capture_output: bool = True):
    """Run argv, trying isolation combinations until one is accepted.

    Order: unshare+limits+session, unshare+session, unshare only,
    limits+session, session, bare subprocess. The first combination that
    does not raise OSError/SubprocessError is the result (including
    non-zero exit).
    """
    cmd = [str(x) for x in cmd]
    unshare = shutil.which('unshare') if isolated else None
    prefixes: list[list[str]] = []
    if unshare:
        prefixes.append([unshare, '--user', '--net', '--ipc', '--uts', '--'])
        prefixes.append([unshare, '--user', '--net', '--'])
        prefixes.append([unshare, '--user', '--'])
    prefixes.append([])
    preexecs = (_apply_limits_and_session, None) if isolated else (None,)

    last_exc: Optional[BaseException] = None
    for prefix in prefixes:
        for pre in preexecs:
            argv = prefix + cmd
            kw = dict(capture_output=capture_output, timeout=timeout, cwd=cwd)
            # start_new_session plus setsid() in preexec_fn races; try each.
            attempts = []
            if pre is _apply_limits_and_session:
                attempts.append(dict(kw, preexec_fn=pre))
                attempts.append(dict(kw, start_new_session=True))
            else:
                attempts.append(dict(kw, start_new_session=True) if isolated else kw)
                attempts.append(kw)
            for extra in attempts:
                try:
                    return subprocess.run(argv, **extra)
                except (OSError, subprocess.SubprocessError) as exc:
                    last_exc = exc
                    continue
    if last_exc:
        raise last_exc
    raise OSError('no host isolation attempt accepted')
