"""Build local snapshots of independent Class 1 peers and run the wire tests."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent


def snapshot(checkout, destination, patch=None):
    destination.mkdir()
    archive = subprocess.check_output(['git', '-C', checkout, 'archive', 'HEAD'])
    subprocess.run(['tar', '-xf', '-', '-C', destination], input=archive, check=True)
    if patch:
        subprocess.run(['git', 'apply', '--unidiff-zero', TOOLS / patch], cwd=destination, check=True)


def build(source, destination, *options):
    subprocess.run(['cmake', '-S', source, '-B', destination, *options], check=True)
    subprocess.run(['cmake', '--build', destination, '--parallel', '4'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('opener', help='OpENer Git checkout')
    parser.add_argument('eipscanner', help='EIPScanner Git checkout')
    parser.add_argument('pytest_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    macos = sys.platform == 'darwin'

    with tempfile.TemporaryDirectory(prefix='cpppo-class1-') as directory:
        work = Path(directory)
        opener, opener_build = work / 'OpENer', work / 'opener-build'
        scanner, scanner_build = work / 'EIPScanner', work / 'scanner-build'
        snapshot(args.opener, opener, 'class1-opener-loopback.patch')
        snapshot(args.eipscanner, scanner, 'class1-eipscanner-loopback.patch')
        darwin_flags = ['-DCMAKE_C_FLAGS=-D_DARWIN_C_SOURCE'] if macos else []
        build(opener / 'source', opener_build, '-DOpENer_PLATFORM=POSIX',
              '-DOpENer_TESTS=OFF', *darwin_flags)
        build(scanner, scanner_build, '-DCMAKE_BUILD_TYPE=Release', '-DTEST_ENABLED=OFF')
        probe = work / 'class1-reference-scanner'
        subprocess.run([
            os.environ.get('CXX', 'c++'), '-std=c++17',
            '-I', scanner / 'src', '-I', scanner_build / 'src',
            TOOLS / 'class1_reference_scanner.cpp', scanner_build / 'src/libEIPScannerS.a',
            '-pthread', '-o', probe,
        ], check=True)
        env = dict(os.environ, CPPPO_OPENER=str(opener_build / 'src/ports/POSIX/OpENer'),
                   CPPPO_EIPSCANNER=str(probe))
        subprocess.run([sys.executable, '-m', 'pytest', 'server/enip/class1_test.py',
                        *args.pytest_args], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    main()
