#!/usr/bin/env python3
"""Produce display-wrapped copies of example JSON files for inclusion in
the I-D, ensuring no rendered line exceeds 72 characters.

The generated *.wrapped.txt files are not valid JSON; long string values
are split with literal newlines so the figures fit within the 72-column
limit required by RFC publication.  The original *.json files remain the
machine-readable source of truth produced by the Go test harness.
"""
import os
import sys

MAX_WIDTH = 72

INPUTS = [
    "jose/examples/ML_DSA_44.jose.json",
    "jose/examples/ML_DSA_65.jose.json",
    "jose/examples/ML_DSA_87.jose.json",
    "cose/examples/ML_DSA_44.cose.json",
    "cose/examples/ML_DSA_65.cose.json",
    "cose/examples/ML_DSA_87.cose.json",
]


def wrap_line(line: str) -> str:
    if len(line) <= MAX_WIDTH:
        return line
    chunks = [line[i : i + MAX_WIDTH] for i in range(0, len(line), MAX_WIDTH)]
    return "\n".join(chunks)


def wrap_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return "\n".join(wrap_line(line) for line in f.read().splitlines()) + "\n"


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in INPUTS:
        src = os.path.join(here, rel)
        dst = src.removesuffix(".json") + ".wrapped.txt"
        content = wrap_file(src)
        with open(dst, "w", encoding="utf-8") as f:
            f.write(content)
        too_long = [
            (i + 1, len(l))
            for i, l in enumerate(content.splitlines())
            if len(l) > MAX_WIDTH
        ]
        if too_long:
            print(f"{dst}: lines still over {MAX_WIDTH}: {too_long}", file=sys.stderr)
            return 1
        print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
