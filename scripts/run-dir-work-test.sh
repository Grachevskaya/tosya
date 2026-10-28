#!/usr/bin/env bash
# What one lookup costs: hidden name against absent name.
#
# scripts/dir_work_test.c drives the block scripts/extract_dir_work.py lifts out of
# src/dir_hook.c -- the same source the kernel gets -- with counters in the shim for
# every lock, allocation, cache question and filesystem call it makes, and around it
# the two namei layers the kernel runs (lookup_fast -> __d_lookup_rcu, lookup_slow ->
# __lookup_slow -> d_alloc_parallel -> i_op->lookup), as android14-6.1 has them.
#
# The same file is built twice more: plain, to show the counters are not a sanitizer
# artifact, and with --coverage, because "how many candidates did dir_hidden() walk"
# is a per-line question and gcov answers it for the lifted source itself.
#
# Usage: scripts/run-dir-work-test.sh [--quick]
#   --quick skips the scaling series.
set -eu
cd "$(dirname "$0")/.."

quick=0
[ "${1:-}" = "--quick" ] && quick=1

python3 -B scripts/extract_dir_work.py || exit 1

asan=build/dir_work_test
plain=build/dir_work_test_plain
cov=build/dir_work_cov
runs=build/dir_work_runs

clang -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -Werror=invalid-pp-token -I build -o "$asan" scripts/dir_work_test.c
clang -std=c23 -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -I build -o "$plain" scripts/dir_work_test.c
gcc --coverage -O0 -g -std=gnu11 -pthread -DTOSYA_WORK_COVERAGE -I build \
  -o "$cov" scripts/dir_work_test.c

scenarios=$("$asan" list | cut -f1)

echo "== one lookup, counted in the shim (asan build) =="
for sc in $scenarios; do "$asan" "$sc" both | grep '^csv,'; done

# The same numbers without the sanitizers: a counter that only agrees under one build
# is a counter that describes the build.
mkdir -p "$runs"
for sc in $scenarios; do
  "$asan" "$sc" both | grep '^csv,'
done > "$runs/asan.csv"
for sc in $scenarios; do
  "$plain" "$sc" both | grep '^csv,'
done > "$runs/plain.csv"
if diff -q "$runs/asan.csv" "$runs/plain.csv" > /dev/null; then
  echo "note: the asan and the plain build report the same counters"
else
  echo "MISMATCH: the asan and the plain build disagree" >&2
  diff "$runs/asan.csv" "$runs/plain.csv" >&2 || true
  exit 1
fi

# ---- per-line counts -------------------------------------------------------
#
# One process per (scenario, mode). The counters are reset after the set is
# installed, so mode=cold counts one walk and mode=both counts two; the difference
# is the second walk, which is the state a repeated stat() finds.
gcdir=
run_cov() { # scenario mode links dir
  sc=$1; mode=$2; links=$3; d=$4
  # A counter file left by an earlier build carries a different checksum, and libgcov
  # then refuses to write: every run starts from none.
  rm -f build/dir_work_cov-dir_work_test.gcda
  mkdir -p "$d"
  if [ -n "$links" ]; then
    "./$cov" "$sc" "$mode" --links "$links" > /dev/null
  else
    "./$cov" "$sc" "$mode" > /dev/null
  fi
  cp build/dir_work_cov-dir_work_test.gcno "$d/x.gcno"
  mv build/dir_work_cov-dir_work_test.gcda "$d/x.gcda"
  rm -f dir_work_block.inc.gcov dir_work_test.c.gcov
  gcov -o "$d" "$d/x.gcda" > "$d/gcov.log" 2>&1 || {
    echo "gcov failed for $sc $mode" >&2
    cat "$d/gcov.log" >&2
    exit 1
  }
  grep -q 'Source:build/dir_work_block.inc' dir_work_block.inc.gcov || {
    echo "gcov found no source for the lifted block ($sc $mode)" >&2
    cat "$d/gcov.log" >&2
    exit 1
  }
  mv dir_work_block.inc.gcov "$d/block.gcov"
  rm -f dir_work_test.c.gcov
}

echo
echo "== per-line counts of the lifted block (gcov) =="
echo "columns: $(python3 -B -c 'import sys; sys.path.insert(0, "scripts"); import dir_work_gcov as m; print(",".join(n for n, _, _ in m.WANTED))')"
for sc in $scenarios; do
  run_cov "$sc" cold "" "$runs/$sc-cold"
  run_cov "$sc" both "" "$runs/$sc-both"
  echo "gcov,$sc,cold,$(python3 -B scripts/dir_work_gcov.py "$runs/$sc-cold/block.gcov")"
  echo "gcov,$sc,warm,$(python3 -B scripts/dir_work_gcov.py "$runs/$sc-both/block.gcov" \
    --subtract "$runs/$sc-cold/block.gcov")"
done

[ "$quick" = 1 ] && exit 0

# ---- does the miss scan grow with the set? ---------------------------------
echo
echo "== a bigger set: candidates walked for one name (gcov, first walk) =="
echo "npad,scenario,hash_calls,hash_iters,own_probes,own_visits,wild_probes,wild_visits"
for n in 0 1 7 63 255; do
  for sc in absent hidden-own-2 caller-miss; do
    d="$runs/scale-$sc-$n"
    run_cov "$sc" cold "$n" "$d" > /dev/null
    python3 -B scripts/dir_work_gcov.py "$d/block.gcov" | \
      awk -F, -v n="$n" -v sc="$sc" '{print n "," sc "," $2 "," $3 "," $5 "," $7 "," $8 "," $10}'
  done
done
