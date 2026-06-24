#!/usr/bin/env python3
"""Create many files quickly to simulate mass file operations.

Usage:
    python create_many_files.py --dir ./tmp --count 500 --size 1024

This is safe for testing: it creates small dummy files and can be removed afterwards.
"""
import os
import argparse
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dir', default='./tmp', help='Target directory')
    p.add_argument('--count', type=int, default=200, help='Number of files to create')
    p.add_argument('--size', type=int, default=512, help='Each file size in bytes')
    args = p.parse_args()

    target = Path(args.dir)
    target.mkdir(parents=True, exist_ok=True)

    sample = b'A' * args.size
    for i in range(args.count):
        fn = target / f'testfile_{i:05d}.dat'
        with open(fn, 'wb') as f:
            f.write(sample)
    print(f'Created {args.count} files in {target.resolve()}')

if __name__ == '__main__':
    main()
