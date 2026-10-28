#!/usr/bin/env bash
# The host tests on the architecture they are about.
#
# The module is arm64 and this machine is not, and the two disagree about things a test can see: the
# inline hook's relocation and its pauth stubs, the width of what the policy tables are read with,
# and every assumption the shadow block makes about a word. Running the same sources through an arm64
# compiler and under qemu answers that without a device, and it is the answer to "does it behave the
# same there" that a host build cannot give.
#
#   aarch64-linux-gnu-gcc and qemu-aarch64-static are the only things needed; every binary is
#   static, so nothing has to be installed beside it.
set -eu
cd "$(dirname "$0")/.."

cc=${ARM_CC:-aarch64-linux-gnu-gcc}
qemu=${ARM_QEMU:-qemu-aarch64-static}

# gnu2x and not c2x: the sources use the asm keyword, which clang takes in every mode and gcc only
# takes when the dialect is the GNU one.
flags="-static -O1 -g -D_GNU_SOURCE -pthread -std=gnu2x"

command -v "$cc" >/dev/null || { echo "missing $cc" >&2; exit 1; }
command -v "$qemu" >/dev/null || { echo "missing $qemu" >&2; exit 1; }

$cc $flags -DTOSYA_HOST_TEST -I src -I scripts/hosttest -I src/include \
  -o build/arm_policy scripts/policy_host_test.c
"$qemu" build/arm_policy

$cc $flags -Wall -Wextra -Wno-unused-function -I src -I src/include -I scripts \
  -o build/arm_inline scripts/inline_reloc_test.c src/inline.c src/inline_entry.c
"$qemu" build/arm_inline

$cc $flags -DTOSYA_HOST_TEST -I src -I src/include -I scripts/hosttest \
  -o build/arm_tiers scripts/tiers_test.c
"$qemu" build/arm_tiers

python3 scripts/extract_shadow.py
$cc -DTOSYA_SHADOW_TEST $flags -I build -I src/include -I scripts/hosttest \
  -o build/arm_shadow scripts/shadow_host_test.c
for mode in early-put no-reuse readd remove reads reclaim contend; do
  "$qemu" build/arm_shadow "$mode"
done

# The directory guard, on the architecture the module is built for.
python3 scripts/extract_dir.py
$cc $flags -I build -o build/arm_dir scripts/dir_host_test.c
"$qemu" build/arm_dir
