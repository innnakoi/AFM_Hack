#!/usr/bin/env python3
"""Open many short TCP connections to a target (default: localhost) to simulate high connection counts.

Usage:
    python network_spammer.py --host 127.0.0.1 --port 9999 --count 200

By default targets localhost and closes sockets immediately; avoid targeting external hosts.
"""
import socket
import argparse
from contextlib import closing

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9999)
    p.add_argument('--count', type=int, default=200)
    args = p.parse_args()

    successes = 0
    for i in range(args.count):
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.settimeout(0.5)
                s.connect((args.host, args.port))
                # optionally send small payload
                try:
                    s.send(b'ping')
                except Exception:
                    pass
                successes += 1
        except Exception:
            # connection refused or timeout is fine for testing
            pass
    print(f'Attempted {args.count} connections to {args.host}:{args.port}, succeeded {successes}')

if __name__ == '__main__':
    main()
