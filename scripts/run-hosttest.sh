#!/usr/bin/env bash
# Host-side unit tests.
#
# policy.c is compiled against the linux/* shims in scripts/hosttest/ and checked against every
# configured (caller, target) pair: catches C-level mistakes the Python model cannot see (word
# sizes, ordering, field mixups).
#
# The ABX reader is C++ and self-contained, so its test is built and run here too, against the
# first bytes of a real packages.xml.
set -eu
cd "$(dirname "$0")/.."

out=build/policy_host_test
cc -O1 -g -DTOSYA_HOST_TEST -I src -I scripts/hosttest -I src/include -o "$out" scripts/policy_host_test.c
"$out"

# The inline hook's runtime half: a real kernel function (find_user, taken from a
# device image) is relocated here, and short trampoline prefixes, native resume
# targets and refusals are checked alongside the entry patch.
inline=build/inline_reloc_test
clang -std=c23 -O1 -Wall -Wextra -Wno-unused-function -I src -I src/include -I scripts -o "$inline" \
  scripts/inline_reloc_test.c src/inline.c src/inline_entry.c
"$inline"

# The fallback chains: the real tiers.c with a table of fakes, so that order,
# forcing and what a revert takes back are checked without a kernel.
tiers=build/tiers_test
clang -std=c23 -O1 -Wall -Wextra -DTOSYA_HOST_TEST -I src -I src/include \
  -I scripts/hosttest -o "$tiers" scripts/tiers_test.c
"$tiers"

# Same sources, one more round under ASan/UBSan: a proxy outliving its owner is not
# a warning, it is a fault the first time it runs.

# The inode shadow block of src/inode_hook.c is kernel-only, so it is extracted and
# driven here. The scenarios pin down what went wrong in it: an inode the package
# manager let go of while it was being read, a table handed to a file it was not
# made for, an open that chained to itself, and a record that was installed even
# though its path could not be stored.
python3 scripts/extract_shadow.py
shadow=build/shadow_test
clang -fsanitize=address,undefined -fno-omit-frame-pointer -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable \
  -Werror=invalid-pp-token -I build -I src/include -I scripts/hosttest -o "$shadow" \
  scripts/shadow_host_test.c
for mode in early-put no-reuse readd kstrdup-fail remove; do
  "$shadow" "$mode"
done

