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
cc -O1 -g -D_GNU_SOURCE -pthread -DTOSYA_HOST_TEST -I src -I scripts/hosttest -I src/include -o "$out" scripts/policy_host_test.c
"$out"

# The inline hook's runtime half: a real kernel function (find_user, taken from a
# device image) is relocated here, and short trampoline prefixes, native resume
# targets and refusals are checked alongside the entry patch.
inline=build/inline_reloc_test
clang -std=c23 -O1 -Wall -Wextra -Wno-unused-function -D_GNU_SOURCE -pthread -I src -I src/include -I scripts -o "$inline" \
  scripts/inline_reloc_test.c src/inline.c src/inline_entry.c
"$inline"

# The fallback chains: the real tiers.c with a table of fakes, so that order,
# forcing and what a revert takes back are checked without a kernel.
tiers=build/tiers_test
clang -std=c23 -O1 -Wall -Wextra -D_GNU_SOURCE -pthread -DTOSYA_HOST_TEST -I src -I src/include \
  -I scripts/hosttest -o "$tiers" scripts/tiers_test.c
"$tiers"

# The directory guard: six protected parent inodes, one visible child, and a caller
# identity the test sets. The matrix is the promise -- ENOENT for the caller a name is
# hidden from, the inode for everyone else, and no dentry left to answer for either.
python3 scripts/extract_dir.py
dir=build/dir_test
clang -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -Werror=invalid-pp-token -I build -o "$dir" scripts/dir_host_test.c
"$dir"

# Same sources, one more round under ASan/UBSan: a proxy outliving its owner is not
# a warning, it is a fault the first time it runs.

# The inode shadow block of src/inode_hook.c is kernel-only, so it is extracted and
# driven here. The scenarios pin down what went wrong in it: an inode the package
# manager let go of while it was being read, a table handed to a file it was not
# made for, an open that chained to itself, and a record that was installed even
# though its path could not be stored.
python3 scripts/extract_shadow.py
shadow=build/shadow_test
clang -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable \
  -DTOSYA_SHADOW_TEST -Werror=invalid-pp-token -I build -I src/include -I scripts/hosttest -o "$shadow" \
  scripts/shadow_host_test.c
# A timeout is part of the harness: a lock taken twice used to hang here instead of failing, and a
# hang is the one result nobody reads.
for mode in early-put no-reuse readd remove reads reclaim sweep-cached timing contend; do
  timeout 120 "$shadow" "$mode"
done

# The same block under the thread sanitizer: six readers and a writer run at once there, and what
# it is there to see is a record freed while a reader could still be inside it, or a lock order that
# does not exist. It is built apart because the address sanitizer and this one cannot share a run.
tsan=build/shadow_tsan
clang -fsanitize=thread -fno-omit-frame-pointer -pthread -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable \
-DTOSYA_SHADOW_TEST   -Werror=invalid-pp-token -I build -I src/include -I scripts/hosttest -o "$tsan" \
  scripts/shadow_host_test.c
TSAN_OPTIONS="suppressions=$PWD/scripts/tsan.supp" timeout 600 "$tsan" contend

# Every host test again under the address and undefined sanitizers, not only the block written for
# them: the same source built this way checks a different set of things, and a fault that only shows
# in one of them is still a fault. The thread sanitizer is not repeated here, because none of these
# three has a second thread to share anything with.
asan=build/policy_host_test_asan
cc -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g -D_GNU_SOURCE -pthread \
  -DTOSYA_HOST_TEST -I src -I scripts/hosttest -I src/include -o "$asan" \
  scripts/policy_host_test.c
"$asan"

asan=build/inline_reloc_test_asan
clang -fsanitize=address,undefined -fno-omit-frame-pointer -std=c23 -O1 -g \
  -Wall -Wextra -Wno-unused-function -D_GNU_SOURCE -pthread -I src -I src/include -I scripts \
  -o "$asan" scripts/inline_reloc_test.c src/inline.c src/inline_entry.c
"$asan"

asan=build/tiers_test_asan
clang -fsanitize=address,undefined -fno-omit-frame-pointer -std=c23 -O1 -g \
  -Wall -Wextra -D_GNU_SOURCE -pthread -DTOSYA_HOST_TEST -I src -I src/include \
  -I scripts/hosttest -o "$asan" scripts/tiers_test.c
"$asan"

plain=build/dir_test_plain
clang -std=c23 -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -I build -o "$plain" scripts/dir_host_test.c
"$plain"

