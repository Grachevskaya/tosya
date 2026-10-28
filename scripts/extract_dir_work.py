#!/usr/bin/env python3
"""Lift the directory-guard block for the cost test.

scripts/extract_dir.py lifts the block the directory host test drives. The one walk
hook's preparation, tosya_dir_walk_last(), lives inside that block, so a test of what
a lookup costs drives exactly the code the inline hook calls. The block is taken from
extract_dir.py's own output, so the tree still has one copy of it.
"""
import pathlib
import subprocess
import sys


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    rc = subprocess.run([sys.executable, str(root / "scripts" / "extract_dir.py")],
                        cwd=root).returncode
    if rc != 0:
        return rc
    block = (root / "build" / "dir_block.inc").read_text()
    out = root / "build" / "dir_work_block.inc"
    out.write_text(block)
    print(f"extract_dir_work: {len(block.splitlines())} lines -> "
          f"{out.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
