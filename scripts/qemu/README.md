# The module in a kernel

`scripts/run-qemu.sh` boots a GKI kernel from the DDK under qemu, loads the module, and drives its
netlink family the way the userspace half does. What it proves is the part a host build cannot: the
inline hooks are arm64 instructions, and this is a kernel executing them.

What a run reaches, on a real GKI kernel with eight cpus:

- the module loads and all four hooks install, each reporting its entry trampoline;
- the netlink family is registered and answers, a request from another family version is refused
  with -EPROTONOSUPPORT, and a stream that was never ended refuses the next one with -EBUSY;
- sixty-four records are pushed, all sixty-four are taken, none is refused, and every one of them
  meets the inode it names: the module reports 64 active, 64 have encountered an inode;
- eight threads through 3200 create, open, read and unlink operations while the stream is pushed
  again and again, with no error from the test and no warning from the kernel;
- after the records are dropped, the module reports no active record and an empty table.

## The disk, and why the run needs one

A record meeting an inode needs a file whose number is the same one a second look would find. The
initramfs filesystem hands numbers out from a counter, so the inode an open builds after the cache is
dropped is not the one the record names: with that filesystem the module correctly reports that no
record has met an inode, and the whole path stays unrun. The run therefore gives the machine a disk,
in the order this platform does it:

1. the image is GPT with a labelled partition and ext4 inside it;
2. the init makes the by-name link and the node the way a ueventd does -- devtmpfs is a module in this
   image and does not load, so /dev starts empty and every node in it is made by hand;
3. the disk is an nvme namespace off a root port of its own, with `iommu=none`. GKI carries nvme and
   no virtio block driver at all, and without that setting the kernel reads no partition table.

## What the disk found

With the files on a real filesystem the records meet their inodes for the first time, and the first
push to end after that deadlocked the task: the stream's ending calls the sweep with the table lock
held, the sweep called the public apply, and apply takes that lock again whenever its lookup misses
-- which is every record of the push that is ending, because the index is only rebuilt after the
sweep has run. The kernel said it plainly: task init blocked for more than 120 seconds, in
mutex_lock, from tosya_apk_shadow_apply, from the sweep, from the stream ending.

The host tests could not have seen it: they stub the lock out, so a second lock was no lock at all.
The sweep now asks for the locked form, and the host harness has a lock that says so when one thread
takes it twice, with a scenario that ends a push while the files it names sit in the cache.
