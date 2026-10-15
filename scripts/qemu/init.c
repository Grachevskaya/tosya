/*
 * What this VM runs: bring up proc and sys, load the module, then drive it the way the userspace half
 * does -- name the files of a directory to the kernel as the apks of an app, let their inodes be
 * made again so the module meets them, ask what it counted, drop them, and finally do the same thing
 * from eight threads at once. A tmpfs in the initramfs is a real filesystem, so the two hooks the
 * module installs are exercised on real inodes here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>

#define CMD_PING 1
#define CMD_BEGIN 2
#define CMD_BATCH 3
#define CMD_END 4
#define CMD_STATUS 5
#define ATTR_BLOB 1
#define KIND_APKS 1u
#define OP_ADD 0u
#define OP_DEL 1u
#define NFILES 64
#define NTHREADS 8
#define NROUNDS 400

static int g_fd = -1;
static int g_family = -1;
static int g_fail = 0;
static unsigned int g_failed, g_failed_total;

struct rec {
	unsigned int op, uid, dev, ino_low, ino_high, path_bytes;
};

static int send_cmd(int cmd, const void *blob, int len)
{
	char buf[8192];
	struct nlmsghdr *nlh = (void *)buf;
	struct genlmsghdr *gh;
	int total = NLMSG_HDRLEN + GENL_HDRLEN;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = g_family;
	/*
	 * ACK, so a stream that is refused says so: without it a handler that returns an error is
	 * silent, and the only way to tell a refusal from an answer is to stop waiting for one.
	 */
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 1;
	gh = (void *)NLMSG_DATA(nlh);
	gh->cmd = cmd;
	gh->version = 6;
	if (blob != NULL && len > 0) {
		struct nlattr *a = (void *)(buf + total);
		a->nla_type = ATTR_BLOB;
		a->nla_len = NLA_HDRLEN + len;
		memcpy((char *)a + NLA_HDRLEN, blob, len);
		total += NLA_ALIGN(a->nla_len);
	}
	nlh->nlmsg_len = total;
	return send(g_fd, buf, total, 0);
}

// One reply, read once: this test asks and looks, it does not pipeline.
static int recv_into(char *buf, int size)
{
	return recv(g_fd, buf, size, 0);
}

static int status_read(unsigned int *inodes, unsigned int *offered,
		       unsigned int *updates)
{
	char buf[8192];
	int n;

	send_cmd(CMD_STATUS, NULL, 0);
	n = recv_into(buf, sizeof(buf));
	if (n < 0)
		return -1;
	struct nlmsghdr *nlh = (void *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return -1;
	struct genlmsghdr *gh = (void *)NLMSG_DATA(nlh);
	int left = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
	struct nlattr *a = (void *)((char *)gh + GENL_HDRLEN);
	for (; left > 0; left -= NLA_ALIGN(a->nla_len),
			 a = (void *)((char *)a + NLA_ALIGN(a->nla_len))) {
		if ((a->nla_type & NLA_TYPE_MASK) == 2 &&
		    a->nla_len >= NLA_HDRLEN + 144) {
			const unsigned int *st =
				(const void *)((char *)a + NLA_HDRLEN);
			*inodes = st[8];
			*offered = st[9];
			// apk_updates is the field after last_error, which is signed and a field of its own.
			*updates = st[13];
			g_failed = st[10];
			g_failed_total = st[11];
			return 0;
		}
	}
	return -1;
}

static int push_adds(const struct rec *recs, int n, const char *const *paths)
{
	char blob[8192];
	unsigned int count = n;
	int at = 4;

	memcpy(blob, &count, 4);
	for (int i = 0; i < n; i++) {
		// A drop carries no path, and the caller says so by passing no array at all.
		int plen = (paths != NULL && paths[i] != NULL) ?
				   (int)strlen(paths[i]) :
				   0;
		memcpy(blob + at, &recs[i], sizeof(recs[i]));
		at += sizeof(recs[i]);
		if (plen > 0) {
			memcpy(blob + at, paths[i], plen);
			at += (plen + 3) & ~3;
		}
	}
	unsigned int kind = KIND_APKS;
	char reply[256];
	int got;

	printf("init: push BEGIN send\n");
	send_cmd(CMD_BEGIN, &kind, 4);
	printf("init: push BEGIN sent\n");
	got = recv_into(reply, sizeof(reply));
	printf("init: push BEGIN reply %d\n", got);
	/*
	 * A request is answered by an error message in either case, and the ones that worked carry a
	 * zero: a reply of that type is a refusal only when the error is not one.
	 */
	if (got > 0 && ((struct nlmsghdr *)reply)->nlmsg_type == NLMSG_ERROR &&
	    ((struct nlmsgerr *)NLMSG_DATA(reply))->error != 0) {
		printf("init: BEGIN refused: %d\n",
		       ((struct nlmsgerr *)NLMSG_DATA(reply))->error);
		return -1;
	}
	printf("init: push BATCH %d bytes\n", at);
	send_cmd(CMD_BATCH, blob, at);
	printf("init: push BATCH sent\n");
	got = recv_into(reply, sizeof(reply));
	printf("init: push BATCH reply %d\n", got);
	if (got > 0 && ((struct nlmsghdr *)reply)->nlmsg_type == NLMSG_ERROR &&
	    ((struct nlmsgerr *)NLMSG_DATA(reply))->error != 0) {
		printf("init: BATCH refused: %d\n",
		       ((struct nlmsgerr *)NLMSG_DATA(reply))->error);
		return -1;
	}
	printf("init: push END send\n");
	send_cmd(CMD_END, NULL, 0);
	got = recv_into(reply, sizeof(reply));
	printf("init: push END reply %d\n", got);
	return 0;
}

static void drop_caches(void)
{
	int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);

	if (fd >= 0) {
		write(fd, "3\n", 2);
		close(fd);
	}
}

/* The inode numbers of a directory, read from its entries: nothing is instantiated, which is what
 * lets the records name files whose inodes do not exist yet. */
// Read the numbers the kernel published for a block device and make its node, the way ueventd does:
// devtmpfs is a module in this image and does not load, so a partition node is not always there.
static int ueventd_by_name(const char *name, const char *sysname)
{
	char path[128], buf[64];
	int fd, n, maj, min;
	char dev[128];

	snprintf(dev, sizeof(dev), "/dev/%s", name);
	if (access(dev, F_OK) == 0) {
		printf("init: %s is already a node\n", dev);
		return 0;
	}
	snprintf(path, sizeof(path), "/sys/class/block/%s/dev", sysname);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("init: cannot read %s: %s\n", path, strerror(errno));
		return -1;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	if (sscanf(buf, "%d:%d", &maj, &min) != 2)
		return -1;
	if (mknod(dev, S_IFBLK | 0600, makedev(maj, min)))
		printf("init: mknod %s: %s\n", dev, strerror(errno));
	printf("init: node %s for %s (%d:%d)\n", dev, sysname, maj, min);
	return 0;
}

// One switch from the kernel command line: the records then carry a number no file can have.
static int cmdline_has(const char *word)
{
	char buf[512];
	int fd = open("/proc/cmdline", O_RDONLY), n;

	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	return strstr(buf, word) != NULL;
}

static unsigned long long now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000ull +
	       (unsigned long long)ts.tv_nsec / 1000ull;
}

// Mounting needs the directory to exist first, and nothing in this rootfs does until it is made.
static void fs_mount(const char *src, const char *dir, const char *type)
{
	int rc;
	if (mkdir(dir, 0755) && errno != EEXIST)
		printf("init: mkdir %s: %s\n", dir, strerror(errno));
	rc = mount(src, dir, type, 0, NULL);
	printf("init: mount %s on %s: %s\n", type, dir,
	       rc ? strerror(errno) : "ok");
}

static int dir_inos(const char *dir, const char **names,
		    unsigned long long *inos, int max)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int n = 0;

	if (d == NULL)
		return -1;
	while ((e = readdir(d)) != NULL && n < max) {
		if (e->d_name[0] == '.')
			continue;
		// Only a regular file can be an apk: the filesystem leaves a lost+found behind, and a
		// directory is not a file whose opens can be routed. d_type says so without instantiating
		// anything, which is what this walk exists to avoid.
		if (e->d_type != DT_REG)
			continue;
		names[n] = strdup(e->d_name);
		inos[n] = e->d_ino;
		n++;
	}
	closedir(d);
	return n;
}

static atomic_int g_done = 0;
static atomic_int g_errors = 0;

static void *worker(void *arg)
{
	long id = (long)arg;
	char path[128];
	char buf[64];
	int fd;

	for (int round = 0; round < NROUNDS; round++) {
		snprintf(path, sizeof(path), "/work/t%ld-%d", id, round);
		fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
		if (fd < 0) {
			atomic_fetch_add(&g_errors, 1);
			continue;
		}
		write(fd, "abcdefgh", 8);
		close(fd);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			ssize_t got = read(fd, buf, sizeof(buf));
			if (got != 8)
				atomic_fetch_add(&g_errors, 1);
			close(fd);
		} else {
			atomic_fetch_add(&g_errors, 1);
		}
		if (unlink(path) != 0)
			atomic_fetch_add(&g_errors, 1);
		atomic_fetch_add(&g_done, 1);
	}
	return NULL;
}

static void load(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int rc;

	if (fd < 0) {
		printf("init: open %s: %s\n", path, strerror(errno));
		return;
	}
	rc = syscall(__NR_finit_module, fd, "", 0);
	printf("init: finit_module -> %d %s\n", rc,
	       rc ? strerror(errno) : "(loaded)");
	close(fd);
}

static int g_nomatch;
static unsigned long long g_tprev;

int main(void)
{
	struct sockaddr_nl sa;
	struct stat st;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	char names_buf[NFILES][64];
	const char *names[NFILES];
	unsigned long long inos[NFILES];
	struct rec recs[NFILES];
	unsigned int inodes = 0, offered = 0, updates = 0;
	int n, i;

	int rc;

	/*
	 * devtmpfs first: the kernel makes the device nodes itself, so the disk below is at a path
	 * without this program having to know a major number.
	 */
	mkdir("/dev", 0755);
	fs_mount("devtmpfs", "/dev", "devtmpfs");
	fs_mount("proc", "/proc", "proc");
	fs_mount("sysfs", "/sys", "sysfs");
	/*
	 * The files are on a disk, not in the initramfs: their inode numbers have to be the same ones
	 * a second look would find, and a tmpfs hands out new numbers from a counter every time.
	 */
	mkdir("/work", 0700);
	/*
	 * The way Android names a partition: ueventd makes a link under by-name for every label in
	 * the table, and a mount names that link instead of a controller path. This program is not
	 * ueventd, so it makes the link itself; the fallback is the node the kernel would have made.
	 */
	mkdir("/dev/block", 0755);
	mkdir("/dev/block/by-name", 0755);
	ueventd_by_name("nvme0n1p1", "nvme0n1p1");
	symlink("/dev/nvme0n1p1", "/dev/block/by-name/userdata");
	rc = mount("/dev/block/by-name/userdata", "/work", "ext4", 0, NULL);
	if (rc)
		rc = mount("/dev/nvme0n1p1", "/work", "ext4", 0, NULL);
	printf("init: by-name/userdata on /work: %s\n",
	       rc ? strerror(errno) : "ok");
	load("/tosya.ko");

	g_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	bind(g_fd, (void *)&sa, sizeof(sa));
	// A reply that never comes is not a hang: a request the module answers nothing to is fine.
	setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	{
		char buf[4096];
		char nm[] = "tosya";
		struct nlmsghdr *nlh = (void *)buf;
		struct genlmsghdr *gh;
		int total = NLMSG_HDRLEN + GENL_HDRLEN;
		struct nlattr *a;

		memset(buf, 0, sizeof(buf));
		nlh->nlmsg_type = GENL_ID_CTRL;
		nlh->nlmsg_flags = NLM_F_REQUEST;
		nlh->nlmsg_seq = 1;
		gh = (void *)NLMSG_DATA(nlh);
		gh->cmd = CTRL_CMD_GETFAMILY;
		gh->version = 1;
		a = (void *)(buf + total);
		a->nla_type = CTRL_ATTR_FAMILY_NAME;
		a->nla_len = NLA_HDRLEN + sizeof(nm);
		memcpy((char *)a + NLA_HDRLEN, nm, sizeof(nm));
		total += NLA_ALIGN(a->nla_len);
		nlh->nlmsg_len = total;
		send(g_fd, buf, total, 0);
		n = recv(g_fd, buf, sizeof(buf), 0);
		if (n > 0) {
			struct nlmsghdr *r = (void *)buf;
			struct genlmsghdr *rg = (void *)NLMSG_DATA(r);
			int left = r->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			struct nlattr *ra = (void *)((char *)rg + GENL_HDRLEN);
			for (; left > 0;
			     left -= NLA_ALIGN(ra->nla_len),
			     ra = (void *)((char *)ra + NLA_ALIGN(ra->nla_len)))
				if ((ra->nla_type & NLA_TYPE_MASK) ==
				    CTRL_ATTR_FAMILY_ID) {
					unsigned short id;
					memcpy(&id, (char *)ra + NLA_HDRLEN, 2);
					g_family = id;
				}
		}
	}
	printf("init: %d cpus, family %d\n", (int)sysconf(_SC_NPROCESSORS_ONLN),
	       g_family);
	if (g_family <= 0) {
		printf("init: no family, stopping\n");
		goto out;
	}

	/* The files exist once, so their names and numbers are real, and then their inodes are let go:
	 * what the records name is what a later open will build again. */
	// The cache goes first, so every open builds its inode again and the rule reaches it through the
	// hook rather than through the sweep a push runs.
	drop_caches();
	for (i = 0; i < NFILES; i++) {
		snprintf(names_buf[i], sizeof(names_buf[i]), "f%03d", i);
		char p[128];
		snprintf(p, sizeof(p), "/work/%s", names_buf[i]);
		int fd = open(p, O_CREAT | O_WRONLY, 0600);
		write(fd, "x", 1);
		close(fd);
	}
	drop_caches();
	n = dir_inos("/work", names, inos, NFILES);
	printf("init: %d files named from the directory\n", n);
	for (i = 0; i < n; i++) {
		recs[i].op = OP_ADD;
		recs[i].uid = 10000u + 123u;
		recs[i].dev = 0;
		recs[i].ino_low = (unsigned int)inos[i];
		recs[i].ino_high = (unsigned int)(inos[i] >> 32);
		recs[i].path_bytes = (unsigned int)strlen(names[i]);
		char p[128];
		snprintf(p, sizeof(p), "/work/%s", names[i]);
		if (stat(p, &st) == 0) {
			recs[i].dev = (unsigned int)st.st_dev;
			recs[i].ino_low = (unsigned int)st.st_ino;
			recs[i].ino_high =
				(unsigned int)((unsigned long long)st.st_ino >>
					       32);
		}
	}
	g_nomatch = cmdline_has("tosya.nomatch");
	g_tprev = now_us();
	if (g_nomatch)
		for (i = 0; i < n; i++)
			recs[i].ino_high = 1u; /* a number no file can have */
	// One stream per file: the module answers each end with its own line saying how many of its
	// records met an inode, so a file that was never met is named by the pair.
	if (cmdline_has("tosya.probe")) {
		for (i = 0; i < n; i++) {
			struct rec one = recs[i];
			struct stat st;
			char p[128];
			int sr;

			snprintf(p, sizeof(p), "/work/%s", names[i]);
			sr = stat(p, &st);
			one.path_bytes = 0;
			printf("init: probe %d %s low=%u high=%u dev=%u stat=%d",
			       i, names[i], one.ino_low, one.ino_high, one.dev,
			       sr);
			puts("");
			push_adds(&one, 1, NULL);
		}
	}
	printf("init: pushing %d records\n", n);
	push_adds(recs, n, names);
	status_read(&inodes, &offered, &updates);
	printf("init: t_push %llu ms", (now_us() - g_tprev) / 1000ull);
	puts("");
	g_tprev = now_us();
	printf("init: after push: inodes=%u offered=%u updates=%u\n", inodes,
	       offered, updates);

	/* Nothing has opened them since the push, so the records have met no inode yet. Opening is what
	 * makes one, and that is where the module puts its table on. */
	for (i = 0; i < n; i++) {
		char p[128];
		int fd;
		snprintf(p, sizeof(p), "/work/%s", names[i]);
		fd = open(p, O_RDONLY);
		if (fd >= 0)
			close(fd);
	}
	status_read(&inodes, &offered, &updates);
	printf("init: t_opens %llu ms", (now_us() - g_tprev) / 1000ull);
	puts("");
	g_tprev = now_us();
	printf("init: after opens: inodes=%u offered=%u updates=%u\n", inodes,
	       offered, updates);

	/* Eight threads through create, open, read and unlink while the ledger is pushed again: the
	 * index, the records and the two locks are all under contention for real here. */
	pthread_t th[NTHREADS];
	for (long t = 0; t < NTHREADS; t++)
		pthread_create(&th[t], NULL, worker, (void *)t);
	for (int round = 0; round < 40; round++) {
		push_adds(recs, n, names);
		usleep(20000);
	}
	for (int t = 0; t < NTHREADS; t++)
		pthread_join(th[t], NULL);
	status_read(&inodes, &offered, &updates);
	printf("init: t_stress %llu ms", (now_us() - g_tprev) / 1000ull);
	puts("");
	g_tprev = now_us();
	printf("init: stress: %d ops, %d errors, inodes=%u updates=%u\n",
	       atomic_load(&g_done), atomic_load(&g_errors), inodes, updates);

	// Dropping what was named, with the push that follows it, gives the records back.
	for (i = 0; i < n; i++) {
		recs[i].op = OP_DEL;
		recs[i].path_bytes = 0;
		char p[128];
		snprintf(p, sizeof(p), "/work/%s", names[i]);
		unlink(p);
	}
	drop_caches();
	push_adds(recs, n, NULL);
	status_read(&inodes, &offered, &updates);
	printf("init: t_drops %llu ms", (now_us() - g_tprev) / 1000ull);
	puts("");
	g_tprev = now_us();
	printf("init: after drops: inodes=%u offered=%u updates=%u failed=%u total=%u\n",
	       inodes, offered, updates, g_failed, g_failed_total);

out:
	printf("init: done, %d errors\n", atomic_load(&g_errors));
	sync();
	reboot(RB_POWER_OFF);
	/*
	 * A reboot that does not take must not end this process: init leaving is a panic, and a panic
	 * hides whatever the machine was doing at the time.
	 */
	for (;;)
		sleep(3600);
}
