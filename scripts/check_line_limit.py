#!/usr/bin/env python3
"""Fail when a file under crates/**/src is longer than 500 lines.

Paths under tests/ or fuzz/ are not part of this gate.
"""

import sys
from pathlib import Path

LIMIT = 500
SKIP = {"tests", "fuzz"}


def main():
    root = Path(__file__).resolve().parent.parent
    failed = False
    for src in sorted((root / "crates").glob("*/src")):
        if not src.is_dir():
            continue
        for path in sorted(src.rglob("*.rs")):
            if SKIP.intersection(path.parts):
                continue
            count = len(path.read_text(encoding="utf-8").splitlines())
            if count > LIMIT:
                rel = path.relative_to(root)
                print(f"{rel}: {count} lines exceeds {LIMIT}", file=sys.stderr)
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
