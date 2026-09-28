#!/usr/bin/env python3
"""Fail when a production Rust file reaches 500 lines.

Production files are the `.rs` files under `crates/*/src`. Integration tests,
unit-test modules split into their own `tests.rs`, examples, and benches are
exempt, and so are the data files listed in `EXEMPT` (they declare the
exemption in their own header).
"""

import sys
from pathlib import Path

LIMIT = 500
ROOT = Path(__file__).resolve().parent.parent
EXEMPT = {Path("crates/seed/src/en_words.rs")}


def production_files():
    for path in sorted(ROOT.glob("crates/*/src/**/*.rs")):
        relative = path.relative_to(ROOT)
        if relative not in EXEMPT and path.name != "tests.rs":
            yield relative


def main():
    over = []
    for relative in production_files():
        with open(ROOT / relative, encoding="utf-8") as handle:
            count = sum(1 for _ in handle)
        if count >= LIMIT:
            over.append((count, relative))
    for count, relative in over:
        print(f"{relative}: {count} lines (limit: under {LIMIT})")
    if over:
        return 1
    print(f"ok: every production file is under {LIMIT} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
