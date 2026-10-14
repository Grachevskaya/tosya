// SPDX-License-Identifier: GPL-2.0
/*
 * netlink.c - privileged BEGIN/BATCH/END streams (include/kaux.h).
 * One netlink port owns the stream until END or a five-second idle timeout.
 * Policy pairs are collected and replaced at END. APK records apply incrementally;
 * END reports per-record failures and counts active records. Token and name batches have
 * their own layouts and must never overwrite the APK status counters.
 */

#include "tosya.h"
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h> /* LINUX_VERSION_CODE for the resv_start_op guard */
#include <linux/string.h>
#include <net/genetlink.h>

#include "kaux.h"

// One message, and one page of a stream, whichever the client sends.
#define KAUX_BATCH_BYTES 32768u

// The policy is collected for the length of a stream and applied at END.
#define KAUX_POLICY_BYTES (4u * 1024u * 1024u)

// The stream in progress: its kind, whether one is open, and the policy so far.
static DEFINE_MUTEX(g_stream_lock);
/* Applying a stream resolves paths and touches inodes, which can sleep: the
 * stream lock is not the one to hold across it, or the next batch of the next
 * upload waits on it. */
static DEFINE_MUTEX(g_apply_lock);
static u32 g_token[4]; /* the name both halves use, as it arrived */
static bool g_open; // a BEGIN without its END yet
static u32 g_owner;
static unsigned long g_deadline;
static u32 g_kind;
static u32 *g_policy; // the pairs collected for the stream in progress
static u32 g_policy_words;
static u32 g_policy_cap;
static u32 g_offered; // records this stream carried, for the status reply
static u32 g_failed; // of those, how many did not land

// Defined with its ops below; the status reply names it.
static struct genl_family kaux_family;

static int kaux_version(struct genl_info *info)
{
	return info->genlhdr->version == KAUX_FAMILY_VERSION ? 0 :
							       -EPROTONOSUPPORT;
}

static int kaux_blob(struct genl_info *info, const u32 **p, u32 *len)
{
	if (kaux_version(info))
		return -EPROTONOSUPPORT;
	if (!info->attrs[KAUX_ATTR_BLOB])
		return -EINVAL;
	*p = nla_data(info->attrs[KAUX_ATTR_BLOB]);
	*len = nla_len(info->attrs[KAUX_ATTR_BLOB]);
	if (*len < 4 || (*len & 3) || *len > KAUX_BATCH_BYTES) {
		/*
		 * Speak up: a silent refusal stops the whole upload here, and all the client
		 * knows is that the kernel said no -- it shows up as an empty apk table.
		 */
		pr_warn("tosya: a netlink payload of %u byte(s) was refused (cap %u)\n",
			*len, KAUX_BATCH_BYTES);
		return -EINVAL;
	}
	return 0;
}

// blob: struct kaux_begin -- the kind of set this stream carries
static int kaux_begin(struct sk_buff *skb, struct genl_info *info)
{
	const struct kaux_begin *b;
	const u32 *p;
	u32 len;
	int rc;

	rc = kaux_blob(info, &p, &len);
	if (rc || len < sizeof(*b))
		return -EINVAL;
	b = (const struct kaux_begin *)p;
	if (b->kind > KAUX_KIND_MAX)
		return -EINVAL;

	mutex_lock(&g_apply_lock);
	mutex_lock(&g_stream_lock);
	if (g_open && time_before(jiffies, g_deadline)) {
		mutex_unlock(&g_stream_lock);
		mutex_unlock(&g_apply_lock);
		return -EBUSY;
	}
	g_owner = info->snd_portid;
	g_deadline = jiffies + 5 * HZ;
	g_open = true;
	g_kind = b->kind;
	g_offered = 0;
	g_failed = 0;
	g_policy_words = 0;
	mutex_unlock(&g_stream_lock);
	mutex_unlock(&g_apply_lock);
	return 0;
}

// The apk side: one record is one apk or library, and it lands right here.
static int kaux_batch_apks(const struct kaux_batch *b, const u32 *p, u32 words)
{
	u32 i = 0,
	    at = 1; // one word of header (count); no generation on the wire
	u32 failed = 0;

	for (i = 0; i < b->count; i++) {
		const struct kaux_apk_rec *r;
		const char *path;
		u64 ino;

		if (at + KAUX_APK_REC_WORDS > words)
			return -EINVAL;
		r = (const struct kaux_apk_rec *)(p + at);
		/*
		 * A drop carries no path: the file is gone, and the module's ledger only has
		 * (dev, ino) left for it. ADD carries a diagnostic path; identity is authoritative.
		 */
		if (r->op > KAUX_OP_MAX ||
		    (r->op == KAUX_OP_ADD && r->path_bytes == 0))
			return -EINVAL;
		if (r->path_bytes > (words - at - KAUX_APK_REC_WORDS) * 4u)
			return -EINVAL;
		path = (const char *)(p + at + KAUX_APK_REC_WORDS);
		ino = r->ino_high;
		ino = (ino << 32) | r->ino_low;

		if (tosya_apk_stream(r->op, r->uid, r->dev, ino, path,
				     r->path_bytes))
			failed++;

		// The path pads the record out to a four byte boundary.
		at += KAUX_APK_REC_WORDS + (r->path_bytes + 3u) / 4u;
	}

	if (failed) {
		g_failed += failed;
		pr_warn("tosya: %u of %u record(s) in a batch did not land\n",
			failed, b->count);
	}
	return 0;
}

// The policy side: collected, because a policy is replaced and not edited.
static int kaux_batch_policy(const struct kaux_batch *b, const u32 *p,
			     u32 words)
{
	u32 need, i;
	int rc = 0;

	if (b->count > (words - 1) / KAUX_POLICY_REC_WORDS)
		return -EINVAL;

	mutex_lock(&g_stream_lock);
	need = g_policy_words + b->count * KAUX_POLICY_REC_WORDS;
	if (need > KAUX_POLICY_BYTES / 4u) {
		rc = -E2BIG;
		goto out;
	}
	if (need > g_policy_cap) {
		u32 cap = g_policy_cap * 2u;
		u32 *grown;

		if (cap < 4096u)
			cap = 4096u;
		while (cap < need)
			cap *= 2u;
		grown = kvcalloc(cap, sizeof(*grown), GFP_KERNEL);
		if (grown == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		if (g_policy_words)
			memcpy(grown, g_policy,
			       g_policy_words * sizeof(*grown));
		kvfree(g_policy);
		g_policy = grown;
		g_policy_cap = cap;
	}

	for (i = 0; i < b->count; i++) {
		const struct kaux_policy_rec *r =
			(const struct kaux_policy_rec
				 *)(p + 1 + i * KAUX_POLICY_REC_WORDS);

		if (r->op != KAUX_OP_ADD) {
			rc = -EINVAL;
			goto out;
		}
		g_policy[g_policy_words++] = r->caller;
		g_policy[g_policy_words++] = r->target;
	}

out:
	mutex_unlock(&g_stream_lock);
	return rc;
}

// blob: struct kaux_batch, then count records
static int kaux_batch(struct sk_buff *skb, struct genl_info *info)
{
	const struct kaux_batch *b;
	const u32 *p;
	u32 len, words;
	int rc = kaux_blob(info, &p, &len);

	if (rc)
		return rc;
	b = (const struct kaux_batch *)p;
	words = len / 4u;
	mutex_lock(&g_apply_lock);
	mutex_lock(&g_stream_lock);
	if (!g_open || g_owner != info->snd_portid) {
		mutex_unlock(&g_stream_lock);
		mutex_unlock(&g_apply_lock);
		return -EPERM;
	}
	g_deadline = jiffies + 5 * HZ;
	g_offered += b->count;
	mutex_unlock(&g_stream_lock);

	switch (g_kind) {
	case KAUX_KIND_POLICY:
		rc = kaux_batch_policy(b, p, words);
		break;
	case KAUX_KIND_TOKEN:
		// The first word is the batch count, NOT a word of the secret.
		if (b->count != 4u || words != 5u) {
			rc = -EINVAL;
			break;
		}
		memcpy(g_token, p + 1, sizeof(g_token));
		break;
	case KAUX_KIND_APKS:
		rc = kaux_batch_apks(b, p, words);
		break;
	default:
		rc = -EINVAL;
	}
	if (rc) {
		mutex_lock(&g_stream_lock);
		g_open = false;
		mutex_unlock(&g_stream_lock);
	}
	mutex_unlock(&g_apply_lock);
	return rc;
}

// One owner through END. BEGIN cannot overwrite the policy buffer during apply.
static int kaux_end(struct sk_buff *skb, struct genl_info *info)
{
	u32 kind, words, offered, failed;
	int rc = kaux_version(info);

	if (rc)
		return rc;
	mutex_lock(&g_apply_lock);
	mutex_lock(&g_stream_lock);
	if (!g_open || g_owner != info->snd_portid) {
		mutex_unlock(&g_stream_lock);
		mutex_unlock(&g_apply_lock);
		return -EPERM;
	}
	kind = g_kind;
	words = g_policy_words;
	offered = g_offered;
	failed = g_failed;
	g_open = false;
	g_kind = 0;
	g_offered = 0;
	mutex_unlock(&g_stream_lock);

	if (kind == KAUX_KIND_POLICY) {
		policy_apply(g_policy, words / 2u);
	} else if (kind == KAUX_KIND_APKS) {
		u32 left = tosya_apk_stream_finish();
		pr_info("tosya: apk stream: %u record(s), %u in the table, %u refused\n",
			offered, left, failed);
		tosya_status_set_apks(left, offered, failed);
		if (failed)
			rc = -EIO;
	}
	mutex_unlock(&g_apply_lock);
	return rc;
}

static int kaux_ping(struct sk_buff *skb, struct genl_info *info)
{
	if (kaux_version(info))
		return -EPROTONOSUPPORT;

	/* A command id that lands here instead of where it belongs would otherwise
	 * look like a success, because a ping is answered with an ACK like
	 * anything else. */
	pr_info("tosya: netlink ping\n");
	return 0;
}

/*
 * How the module is doing, as one fixed structure (kaux.h): what it hooked, and
 * what it failed to. This is the only command that answers with data.
 */
static int kaux_status(struct sk_buff *skb, struct genl_info *info)
{
	struct kaux_status st;
	struct sk_buff *out;
	void *hdr;

	if (kaux_version(info))
		return -EPROTONOSUPPORT;

	tosya_status_get(&st);

	// APK counters are owned by tosya_status_set_apks, never by token/name streams.

	out = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!out)
		return -ENOMEM;
	mutex_lock(&g_apply_lock);
	memcpy(st.token, g_token, sizeof(g_token));
	mutex_unlock(&g_apply_lock);
	hdr = genlmsg_put_reply(out, info, &kaux_family, 0, KAUX_CMD_STATUS);
	if (hdr == NULL || nla_put(out, KAUX_ATTR_STATUS, sizeof(st), &st)) {
		nlmsg_free(out);
		return -EMSGSIZE;
	}
	genlmsg_end(out, hdr);
	return genlmsg_reply(out, info);
}

static const struct genl_ops kaux_ops[] = {
	{ .cmd = KAUX_CMD_PING, .flags = GENL_ADMIN_PERM, .doit = kaux_ping },
	{ .cmd = KAUX_CMD_STATUS,
	  .flags = GENL_ADMIN_PERM,
	  .doit = kaux_status },
	{ .cmd = KAUX_CMD_BEGIN, .flags = GENL_ADMIN_PERM, .doit = kaux_begin },
	{ .cmd = KAUX_CMD_BATCH, .flags = GENL_ADMIN_PERM, .doit = kaux_batch },
	{ .cmd = KAUX_CMD_END, .flags = GENL_ADMIN_PERM, .doit = kaux_end },
};

static const struct genl_multicast_group kaux_mcgrps[] = {
	{ .name = "events" }
};

static struct genl_family kaux_family = {
	.name = KAUX_FAMILY_NAME,
	.version = KAUX_FAMILY_VERSION,
	.maxattr = KAUX_ATTR_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	.resv_start_op = KAUX_CMD_MAX + 1,
#endif
	.module = THIS_MODULE,
	.ops = kaux_ops,
	.n_ops = ARRAY_SIZE(kaux_ops),
	.mcgrps = kaux_mcgrps,
	.n_mcgrps = ARRAY_SIZE(kaux_mcgrps),
};

int netlink_init(void)
{
	int rc;

	rc = genl_register_family(&kaux_family);

	if (rc)
		pr_err("tosya: cannot register the netlink family '%s' (%d); the tool will not find this module%s\n",
		       KAUX_FAMILY_NAME, rc,
		       rc == -EEXIST ?
			       " -- a previous copy of it may still be loaded" :
			       "");
	else
		pr_info("tosya: netlink family '%s' registered, version %u\n",
			KAUX_FAMILY_NAME, KAUX_FAMILY_VERSION);
	return rc;
}

void netlink_exit(void)
{
	genl_unregister_family(&kaux_family);
	kvfree(g_policy);
	g_policy = NULL;
	g_policy_cap = 0;
	g_policy_words = 0;
}
