#!/usr/bin/env bash
# Run clang-tidy over the module sources.
#
# kbuild-compile-commands.py turns the .cmd files kbuild leaves next to the objects into a database
# carrying the flags the module was really built with. Build first; the KMI analysed is the first
# one under build/kmi. The script is silent when the sources are clean and exits non-zero when they
# are not.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

kmi=$(ls build/kmi 2>/dev/null | head -1)
if [ -z "$kmi" ]; then
  echo "no build/kmi/* -- build the module first" >&2
  exit 1
fi

rc=0

echo "== kernel (compile database from the kbuild .cmd files of $kmi)"
python3 scripts/kbuild-compile-commands.py "$kmi" || rc=1
( cd "/opt/ddk/kdir/$kmi" && clang-tidy -p "$root/build/tidy/kernel" --warnings-as-errors='*' "$root"/src/*.c ) || rc=1

exit $rc
