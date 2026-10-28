#!/usr/bin/env python3
"""Read the per-line counts gcov left for the lifted directory-guard block.

scripts/dir_work_test.c is built with --coverage and its counters are reset after the
name set is installed, so a .gcov file describes the lookups and nothing else. What
this prints is the handful of lines that answer "how much work": the hash loop,
the two fixed probe runs inside dir_hidden_probe() (own pair, then wildcard
pair), the guard scan, the walk preparation and the cold-path mask table, each
as the number of times that line ran.

Usage: dir_work_gcov.py BLOCK.gcov [--subtract EARLIER.gcov]
With --subtract, the difference is printed, which is how the second walk of a name is
separated from the first without a second process having to exist.
"""
import argparse
import re
import sys

# (name, a piece of the source line, which occurrence) -- occurrences are in file
# order, which is the order the block defines them in.
WANTED = (
    ("lookup_calls", "static struct dentry *tosya_lookup(struct inode *dir", 1),
    ("hash_calls", "u64 h = 0xcbf29ce484222325ull;", 1),
    ("hash_iters", "while (len--)", 1),
    ("hidden_calls",
     "static __attribute__((__noinline__)) u32 dir_hidden_probe(", 1),
    ("pair_own_probes", "for (i = 0; i < DIR_PAIR_PROBES; i++) {", 1),
    ("pair_own_reads", "const u32 pair = t->pair[own];", 1),
    ("pair_own_visits",
     "dir_bytes_eq(t->arena + e->name_off, name,", 1),
    ("pair_wild_probes", "for (i = 0; i < DIR_PAIR_PROBES; i++) {", 2),
    ("pair_wild_reads", "const u32 pair = t->pair[wild];", 1),
    ("pair_wild_visits",
     "dir_bytes_eq(t->arena + e->name_off, name,", 2),
    ("guard_visits",
     "if (g != NULL && g->inode == dir && dir->i_op == &g->iop)", 1),
    ("walk_last_calls",
     "bool tosya_dir_walk_last(const struct qstr *last,", 1),
    ("mask_find_calls", "static u32 dir_mask_find(const struct dir_names *s,", 1),
)


# "8*" is a count whose branches were not all taken, "1.5k" a large one.
LINE = re.compile(
    r"^\s*(?P<count>#####|-|\d+(?:\.\d+)?[kM]?)\*?\s*:\s*(?P<line>\d+):(?P<src>.*)$",
    re.S)


def parse_count(raw):
    if raw == "#####":
        return 0
    if raw == "-":
        return None
    if raw[-1] in "kM":
        return int(float(raw[:-1]) * (1000 if raw[-1] == "k" else 1000000))
    return int(raw)


def parse(path):
    """lineno -> count (None for a line the compiler says cannot run)."""
    counts = {}
    text = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LINE.match(line)
            if not m:
                continue
            counts[int(m.group("line"))] = parse_count(m.group("count"))
            text[int(m.group("line"))] = m.group("src")
    return counts, text


def pick(counts, text, needle, occurrence):
    hits = [ln for ln in sorted(text) if needle in text[ln]]
    if len(hits) < occurrence:
        raise SystemExit(
            f"dir_work_gcov: {needle!r} appears {len(hits)} time(s), "
            f"needed {occurrence}")
    ln = hits[occurrence - 1]
    got = counts.get(ln)
    return 0 if got is None else got


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("gcov")
    ap.add_argument("--subtract")
    args = ap.parse_args()

    counts, text = parse(args.gcov)
    values = {name: pick(counts, text, needle, occ)
              for name, needle, occ in WANTED}
    if args.subtract:
        base_counts, base_text = parse(args.subtract)
        base = {name: pick(base_counts, base_text, needle, occ)
                for name, needle, occ in WANTED}
        values = {k: values[k] - base[k] for k in values}
    print(",".join(str(values[name]) for name, _, _ in WANTED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
