#!/usr/bin/env python3
"""Lift the directory-guard block out of src/dir_hook.c for the host test.

The block needs inodes and a dcache, so it is compiled for the kernel only; the
host test needs the same source. It is extracted rather than copied so a change
in one place cannot leave a stale copy in the other, and this refuses to produce
anything when the markers or the pieces they are supposed to contain are gone.
"""
import pathlib
import sys

BEGIN = "/* TOSYA_DIR_BEGIN"
END = "/* TOSYA_DIR_END */"
NEEDED = ("tosya_lookup", "dir_guard_add_inode", "dir_guard_remove_all",
          "dir_names_apply", "dir_stage_add", "dir_mask_make", "dir_hidden_probe",
          "dir_mask_find", "tosya_dir_walk_last", "g->orig->lookup(")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    src = (root / "src" / "dir_hook.c").read_text()
    if BEGIN not in src or END not in src:
        print("extract_dir: the markers are gone from src/dir_hook.c",
              file=sys.stderr)
        return 1
    body = src.split(BEGIN, 1)[1].split("\n", 1)[1].split(END, 1)[0]
    for need in NEEDED:
        if need not in body:
            print(f"extract_dir: the block has no {need!r}", file=sys.stderr)
            return 1
    out = root / "build" / "dir_block.inc"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    print(f"extract_dir: {len(body.splitlines())} lines -> "
          f"{out.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
