#!/usr/bin/env python3
"""Simple CPU stress test for a few seconds.

Usage:
    python cpu_stress.py --workers 4 --duration 30

This will run busy loops in background threads to increase CPU usage.
"""
import threading
import time
import argparse

def worker(stop_event):
    # Busy loop until stop_event is set
    x = 0
    while not stop_event.is_set():
        x += 1

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--workers', type=int, default=2, help='Number of worker threads')
    p.add_argument('--duration', type=int, default=20, help='Duration in seconds')
    args = p.parse_args()

    stop = threading.Event()
    threads = []
    for _ in range(args.workers):
        t = threading.Thread(target=worker, args=(stop,), daemon=True)
        t.start()
        threads.append(t)

    print(f'Started {args.workers} CPU workers for {args.duration}s')
    try:
        time.sleep(args.duration)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=1)
    print('CPU stress finished')

if __name__ == '__main__':
    main()
