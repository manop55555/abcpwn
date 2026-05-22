#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
"""Per-directory coverage gate.

Parses an lcov tracefile and asserts per-directory line-coverage
thresholds. Exits non-zero when any group falls below its target.
Usage:
    check-coverage.py coverage.info [--min-commands N] [--min-formats N]
                                    [--min-arch N] [--min-core N]
                                    [--min-output N]
The thresholds are percentages (0..100).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path


def parse_lcov(path: Path) -> dict[str, tuple[int, int]]:
    """Return {source_file: (lines_hit, lines_found)} from an lcov info."""
    by_file: dict[str, tuple[int, int]] = {}
    current: str | None = None
    hit = found = 0
    for raw in path.read_text(errors="replace").splitlines():
        if raw.startswith("SF:"):
            current = raw[3:].strip()
            hit = found = 0
        elif raw.startswith("LH:"):
            hit = int(raw[3:])
        elif raw.startswith("LF:"):
            found = int(raw[3:])
        elif raw == "end_of_record" and current is not None:
            by_file[current] = (hit, found)
            current = None
    return by_file


def classify(source_path: str) -> str:
    """Return the directory group for a source file.

    Maps src/commands/*  -> commands
         src/formats/*   -> formats
         src/arch/*      -> arch
         src/core/*      -> core
         src/output/*    -> output
         everything else -> 'other' (ignored for thresholds).
    """
    m = re.search(r"/src/(commands|formats|arch|core|output)/", source_path)
    if m:
        return m.group(1)
    return "other"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tracefile", type=Path)
    p.add_argument("--min-commands", type=int, default=0)
    p.add_argument("--min-formats",  type=int, default=0)
    p.add_argument("--min-arch",     type=int, default=0)
    p.add_argument("--min-core",     type=int, default=0)
    p.add_argument("--min-output",   type=int, default=0)
    args = p.parse_args()

    if not args.tracefile.exists():
        print(f"[-] tracefile not found: {args.tracefile}", file=sys.stderr)
        return 2

    files = parse_lcov(args.tracefile)
    if not files:
        print("[-] no SF records in tracefile", file=sys.stderr)
        return 2

    groups: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for sf, (hit, found) in files.items():
        groups[classify(sf)].append((hit, found))

    targets = {
        "commands": args.min_commands,
        "formats":  args.min_formats,
        "arch":     args.min_arch,
        "core":     args.min_core,
        "output":   args.min_output,
    }

    failed = False
    print(f"{'group':<10} {'lines':>8} {'hit':>8} {'pct':>6}  target")
    for group, target in targets.items():
        rows = groups.get(group, [])
        total_found = sum(f for _h, f in rows)
        total_hit   = sum(h for h, _f in rows)
        pct = 100.0 * total_hit / total_found if total_found else 0.0
        status = "[+]" if pct >= target else "[-]"
        print(f"{group:<10} {total_found:>8} {total_hit:>8} {pct:>5.1f}%  >= {target} {status}")
        if pct < target:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
