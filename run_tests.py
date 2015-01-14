#!/usr/bin/env python
"""Run the tests. I give up on doing it the right way."""
import os
import pytest
import argparse

def _split_path(path):
    """os.path.split gives you basename, filename instead of a list."""
    parts = []
    while path:
        path, filename = os.path.split(path)
        parts.append(filename)
    return list(reversed(parts))


def to_cover(path):
    """Handle the hook for a single path with smartcov."""
    spath = _split_path(path)
    parts = []
    found_pyssh = False
    for part in spath:
        if part == 'test':
            parts.append('pyssh')
            found_pyssh = True
        elif found_pyssh and part.startswith('test_'):
            parts.append(part[5:])
        else:
            parts.append(part)
    return '/'.join(parts)



def main():
    """Ugly hacks for pytest + argparse... but at least now I don't need
    pytest.ini.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--include-slow', dest='slow', action='store_true')
    parser.add_argument('files', nargs='*')
    namespace, extra = parser.parse_known_args()
    cmd = ['--strict', '-rf', '--cov-config', 'etc/coveragerc',
           '--cov-report=term-missing'
           ]
    if '--pdb' in extra:
        cmd.append('-x')
    if not namespace.slow:
        cmd.extend(['-m', '"not slow"'])
    cmd.extend(extra)
    if not namespace.files:
        namespace.files = ['test']
    namespace.files = [x.rstrip('/').rstrip('\\').replace('\\', '/')
                       for x in namespace.files]
    cmd.extend('--cov={}'.format(to_cover(f)) for f in namespace.files)
    cmd.extend(namespace.files)
    print(namespace.files)
    print(' '.join(cmd))
    pytest.main(' '.join(cmd))
    os.remove('.coverage')


if __name__ == '__main__':
    main()
