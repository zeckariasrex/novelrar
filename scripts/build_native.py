#!/usr/bin/env python3
"""Explicit build; importing the library never runs a compiler."""
import os
import platform
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if platform.system() != 'Linux':
    raise SystemExit('This build recipe currently supports Linux only.')
output = ROOT / 'build' / 'libnovelrar.so'
output.parent.mkdir(exist_ok=True)
sources = [str(ROOT / 'native/lz4_decode.c'), str(ROOT / 'native/deflate.c'),
           str(ROOT / 'native/nrisa.c')]
if platform.machine() in ('x86_64', 'AMD64'):
    sources.append(str(ROOT / 'native/repeat_x86_64.S'))
subprocess.run([os.environ.get('CC', 'cc'), '-O3', '-std=c11', '-Wall', '-Wextra',
                '-fPIC', '-shared', *sources, '-o', str(output)], check=True)
print(output)
