/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kaux.h - the wire format of the netlink family the userspace half talks to.
 *
 * The module (src/netlink.c) and the userspace half both include this file, so the two
 * ends of the protocol cannot drift apart.
 *
 * This is a streaming protocol, and only the changes travel. A rule set has no
 * ceiling -- every apk, every extracted native library, and every drop the
 * module's ledger computes on a package change -- and staging a whole set in the
 * kernel is what would put one there:
 *
 *   KAUX_CMD_PING    -> ACK                    nothing, alive and version
 *   KAUX_CMD_BEGIN   blob = struct kaux_begin  what the stream is about
 *   KAUX_CMD_BATCH   blob = struct kaux_batch, then its records
 *   KAUX_CMD_END     blob = nothing            this stream is finished
 *   KAUX_CMD_STATUS  -> reply: KAUX_ATTR_STATUS = struct kaux_status
 *
 * A record is applied as it arrives and nothing else happens at the end: the set is
 * exactly what was added and not removed. Drops are records of their own, not an
 * absence -- the module keeps the ledger and says what to remove, so the kernel never
 * has to diff anything and a stream that stops halfway stops.
 *
 * Everything is little endian and a multiple of four bytes long, so the
 * structures below are the wire image as they stand, with no packing.
 */
#ifndef TOSYA_KAUX_H
#define TOSYA_KAUX_H

#ifdef __cplusplus
#define KAUX_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define KAUX_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#define KAUX_FAMILY_NAME "tosya"
#define KAUX_FAMILY_VERSION 5u

// One attribute carries the payload in either direction.
enum {
	KAUX_ATTR_UNSPEC,
	KAUX_ATTR_BLOB, // request payload
	KAUX_ATTR_STATUS, // struct kaux_status, on a STATUS reply
	__KAUX_ATTR_MAX
};
#define KAUX_ATTR_MAX (__KAUX_ATTR_MAX - 1)

enum {
	KAUX_CMD_UNSPEC,
	KAUX_CMD_PING,
	KAUX_CMD_BEGIN,
	KAUX_CMD_BATCH,
	KAUX_CMD_END,
	KAUX_CMD_STATUS,
	__KAUX_CMD_MAX
};
#define KAUX_CMD_MAX (__KAUX_CMD_MAX - 1)

// What a stream is carrying. Both kinds may be uploaded in the same session.
#define KAUX_KIND_POLICY 0u
#define KAUX_KIND_APKS 1u
#define KAUX_KIND_MAX KAUX_KIND_APKS

// What a record does. Added to a set or taken out of it.
#define KAUX_OP_ADD 0u
#define KAUX_OP_DEL 1u
#define KAUX_OP_MAX KAUX_OP_DEL

struct kaux_begin {
	unsigned int kind; // KAUX_KIND_*
};

struct kaux_batch {
	unsigned int count; // records that follow, each self-delimited
};

/*
 * The two record layouts. A record is a fixed head and, for an apk, the path
 * bytes it names, zero pad to a four byte boundary; the next record starts at
 * the head plus that. The head is a multiple of four, so a record's own length
 * is too, and a batch can be walked without a length prefix.
 */
struct kaux_apk_rec {
	unsigned int op; // KAUX_OP_*
	unsigned int uid;
	unsigned int dev; // st_dev of the apk or library
	unsigned int ino_low; // st_ino, which is 64 bit but stored 32 here
	unsigned int ino_high;
	unsigned int path_bytes; // bytes that follow this head
};
#define KAUX_APK_REC_WORDS 6u

// One policy line: the caller, its target, and the verdict's own bits.
struct kaux_policy_rec {
	unsigned int op; // KAUX_OP_*
	unsigned int caller;
	unsigned int target;
	unsigned int flags;
};
#define KAUX_POLICY_REC_WORDS 4u

/* What the module is doing, for the userspace half to show a user. Fixed size, so a
 * mismatch between the two ends is a checked error and not a misread. */
struct kaux_status {
	unsigned int magic; // KAUX_STATUS_MAGIC, so a wrong blob is not read
	unsigned int size; // sizeof(struct kaux_status)
	unsigned int version; // KAUX_FAMILY_VERSION
	// KAUX_F_* below: which of the three registrations are in place
	unsigned int flags;
	unsigned int native; // entries hooked in sys_call_table
	unsigned int native_expected;
	unsigned int compat; // entries hooked in compat_sys_call_table
	unsigned int compat_expected;
	/*
	 * The apk side, which is the other half of what the module does: the
	 * base.apk of every app that has rules has its open replaced, and a child
	 * is named from the one it opens. inodes is how many are held right now --
	 * it drops when an app is removed -- offered is what the last stream
	 * carried, and failed is how many of those could not be put in place.
	 */
	unsigned int apk_inodes;
	unsigned int apk_offered;
	unsigned int apk_failed; // of the last apply
	unsigned int apk_failed_total; // since the module was loaded
	int last_error; // the most recent failure, 0 when there is none
	unsigned int apk_updates; // how many times a stream was ended
	/*
	 * The geometry this module was built for. The userspace half reads the
	 * running kernel's config (/proc/config.gz, which GKI ships) and compares: a device
	 * whose VA size differs puts the fixmap slot somewhere else, which the
	 * patcher proves before it writes, but a user is better served by a line
	 * that says so than by a hook that quietly is not there.
	 */
	unsigned int va_bits;
	unsigned int page_shift;
	char uid_tier[32];
	char setuid_tier[32];
};
// the protocol's marker; "kaux" as bytes, kept as it is
#define KAUX_STATUS_MAGIC 0x7875616bu

#define KAUX_F_NATIVE 0x1u
#define KAUX_F_COMPAT 0x2u
#define KAUX_F_SETUID 0x4u
// the last stream left every entry in place
#define KAUX_F_APKS 0x8u

KAUX_STATIC_ASSERT(sizeof(struct kaux_begin) == 4,
		   "kaux_begin is the wire image");
KAUX_STATIC_ASSERT(sizeof(struct kaux_batch) == 4,
		   "kaux_batch is the wire image");
KAUX_STATIC_ASSERT(sizeof(struct kaux_apk_rec) == 24,
		   "kaux_apk_rec is the wire image");
KAUX_STATIC_ASSERT(sizeof(struct kaux_policy_rec) == 16,
		   "kaux_policy_rec is the wire image");

#endif
