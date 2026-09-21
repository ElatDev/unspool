"""Throw malformed captures at unspool and report anything that isn't a clean error.

    python tools/fuzz.py --cases 1000000
    python tools/fuzz.py --seconds 300 --jobs 8

A parser's real job is refusing bad input politely. Every case here is a valid
synthetic capture with something broken in it: flipped bits, truncations,
corrupt length fields, spliced noise. The run fails if any input produces an
exception that is not an ``unspool.UnspoolError``, or takes longer than
``--slow`` seconds (a hang is as bad as a crash).

Anything that does fail is written to ``.cache/fuzz-failures`` so it can be
replayed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests import fuzzing  # noqa: E402

FAILURES = ROOT / ".cache" / "fuzz-failures"


def chunk(count: int, seed: int, slow: float) -> fuzzing.Result:
    result = fuzzing.Result()
    for case in fuzzing.cases(count, seed):
        fuzzing.run_case(case, result, slow_seconds=slow)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cases", type=int, default=100_000, help="inputs to try")
    parser.add_argument("--seconds", type=float, help="stop after this long instead")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--slow", type=float, default=2.0,
                        help="flag any single input taking longer than this")
    args = parser.parse_args()

    started = time.monotonic()
    total = fuzzing.Result()
    batch = 2000
    seed = args.seed
    done = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
        while True:
            pending = min(args.jobs, max(1, (args.cases - done + batch - 1) // batch)) \
                if not args.seconds else args.jobs
            futures = []
            for _ in range(pending):
                size = batch if args.seconds else min(batch, args.cases - done)
                if size <= 0:
                    break
                futures.append(pool.submit(chunk, size, seed, args.slow))
                seed += 1
                done += size
            if not futures:
                break
            for future in futures:
                result = future.result()
                total.parsed += result.parsed
                total.rejected += result.rejected
                total.packets += result.packets
                total.crashes.extend(result.crashes)
                total.slow.extend(result.slow)
            elapsed = time.monotonic() - started
            rate = done / elapsed if elapsed else 0
            print(f"\r{done:,} inputs · {rate:,.0f}/s · {total.parsed:,} parsed · "
                  f"{total.rejected:,} rejected · {len(total.crashes)} crashes", end="",
                  flush=True)
            if args.seconds and elapsed >= args.seconds:
                break
            if not args.seconds and done >= args.cases:
                break

    elapsed = time.monotonic() - started
    print()
    print(f"{done:,} malformed inputs in {elapsed:.1f}s "
          f"({done / elapsed:,.0f}/s, {total.packets:,} packets decoded)")
    print(f"  parsed without error: {total.parsed:,}")
    print(f"  refused with an UnspoolError: {total.rejected:,}")
    print(f"  unhandled exceptions: {len(total.crashes)}")
    print(f"  inputs slower than {args.slow}s: {len(total.slow)}")
    if total.crashes or total.slow:
        FAILURES.mkdir(parents=True, exist_ok=True)
        for case, exc in total.crashes:
            path = FAILURES / f"crash-{case.seed}.pcapng"
            path.write_bytes(case.data)
            print(f"  {type(exc).__name__}: {exc} -> {path}")
        for case, seconds in total.slow:
            path = FAILURES / f"slow-{case.seed}.pcapng"
            path.write_bytes(case.data)
            print(f"  slow ({seconds:.1f}s) -> {path}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
