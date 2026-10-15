#!/usr/bin/env bash
# The module, in a real kernel, on the architecture it is built for.
#
# The host tests run the sources through a compiler; this runs the built module through a kernel. It
# is the only place the inline hooks are exercised for real: the trampolines they write and the
# pauth stubs they choose are arm64 instructions, and a GKI kernel is what will execute them.
#
#   The DDK ships a vmlinux per KMI, and it is a position independent ELF: qemu cannot load that as
#   a kernel image, so it is taken out to the flat Image the arm64 boot protocol asks for. The
#   initramfs is one static init that mounts proc and sys, loads the module, drives its netlink
#   family the way the userspace half does, and powers the machine off.
#
#   The disk is part of the test, not a convenience: a record meeting an inode needs a file whose
#   number a second look would find again, and the initramfs filesystem hands numbers out from a
#   counter. It is a GPT image with a labelled partition and ext4 inside, attached as an nvme
#   namespace -- GKI carries nvme and no virtio block driver -- off a root port of its own, with the
#   iommu out of the way, which is what lets the kernel read the table at all.
#
#   scripts/run-qemu.sh [kmi]        default: android14-6.1
set -eu
cd "$(dirname "$0")/.."

kmi=${1:-android14-6.1}
ddk=${DDK_ROOT:-/opt/ddk}
cc=${ARM_CC:-aarch64-linux-gnu-gcc}
qemu=${ARM_QEMU_SYS:-qemu-system-aarch64}
objcopy=${ARM_OBJCOPY:-aarch64-linux-gnu-objcopy}

for t in "$cc" "$qemu" "$objcopy"; do
  command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }
 done

root=build/qemu
ko=build/ko/${kmi}_arm64_tosya.ko
[ -f "$ko" ] || { echo "no $ko -- build the module first" >&2; exit 1; }

mkdir -p "$root/root"
"$cc" -static -O1 -g -std=gnu2x -o "$root/root/init" scripts/qemu/init.c
cp "$ko" "$root/root/tosya.ko"
( cd "$root/root" && find . | cpio -o -H newc --quiet > "../initramfs.cpio" )
"$objcopy" -O binary "$ddk/kdir/$kmi/vmlinux" "$root/Image"

img=$root/apks.img
if [ ! -f "$img" ]; then
  truncate -s 64M "$img"
  sgdisk -Z -n 1:2048:0 -c 1:userdata -t 1:8300 "$img" >/dev/null
  mke2fs -q -t ext4 -O ^orphan_file,^metadata_csum_seed,^64bit,^metadata_csum -I 256 -b 4096 \
    -E offset=$((2048 * 512)) -F "$img" 12288
fi

echo "== $kmi, 8 cpus, $(stat -c%s "$root/Image") byte image, $(stat -c%s "$img") byte disk"
timeout 900 "$qemu" -M virt,gic-version=3,iommu=none -cpu max -smp 8 -m 2048 \
  -kernel "$root/Image" -initrd "$root/initramfs.cpio" \
  -device pcie-root-port,id=pcie_port1,chassis=1,slot=1 \
  -device nvme,id=nvme_ctrl0,serial=nvme-123456,bus=pcie_port1 \
  -drive file="$img",if=none,id=hd_user,format=raw,file.locking=off \
  -device nvme-ns,drive=hd_user,bus=nvme_ctrl0,nsid=1,uuid=12345678-1234-1234-1234-123456789abc,nguid=12345678123412341234123412341234,eui64=0x0011223344556677 \
  -append 'console=ttyAMA0,115200 rdinit=/init loglevel=7' \
  -nographic -no-reboot
