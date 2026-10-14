#!/usr/bin/env python3
"""Compile the production BEGIN/BATCH/END handlers against a deterministic kernel shim."""
from pathlib import Path
import subprocess
import os
root = Path(__file__).resolve().parents[1]
source = (root / 'src/netlink.c').read_text()
start = source.index('static int kaux_begin(')
end = source.index('static int kaux_ping(')
handlers = source[start:end]
assert all(('static int ' + name + '(') in handlers for name in ['kaux_begin', 'kaux_batch', 'kaux_end', 'kaux_batch_apks', 'kaux_batch_policy'])
out = root / '.scratch/tests/netlink'
out.mkdir(parents=True, exist_ok=True)
shim = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include "kaux.h"
typedef uint32_t u32;
typedef uint64_t u64;
struct sk_buff { int unused; };
struct genl_info { u32 snd_portid; const u32 *data; u32 len; };
#define HZ 100
#define GFP_KERNEL 0
#define KAUX_POLICY_BYTES (4u * 1024u * 1024u)
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define kvcalloc(n,s,f) calloc(n,s)
#define kvfree(p) free(p)
#define time_before(a,b) ((long)((a)-(b)) < 0)
static unsigned long jiffies;
static int g_stream_lock, g_apply_lock;
static void mutex_lock(int *m) { assert(!*m); *m=1; }
static void mutex_unlock(int *m) { assert(*m); *m=0; }
static bool g_open;
static u32 g_owner, g_kind, g_offered, g_failed, g_policy_words, g_policy_cap, g_last_offered;
static unsigned long g_deadline;
static u32 *g_policy, g_token[4];
static u32 policy_n, status_calls, last_failed;
static u32 seen_dev; static u64 seen_ino;
static int kaux_version(struct genl_info *i) { return 0; }
static int kaux_blob(struct genl_info *i, const u32 **p, u32 *len) { *p=i->data; *len=i->len; return (*len<4 || *len%4) ? -EINVAL : 0; }
static void policy_apply(const u32 *p,u32 n) { policy_n=n; }
static int tosya_apk_stream(u32 op,u32 uid,u32 dev,u64 ino,const char *path,u32 len) { seen_dev=dev; seen_ino=ino; return !ino ? -EINVAL : 0; }
static u32 tosya_apk_stream_finish(void) { return 1; }
static void tosya_status_set_apks(u32 left,u32 offered,u32 failed) { status_calls++; last_failed=failed; }
'''
main = r'''
static int begin(u32 owner,u32 kind) { struct genl_info i={owner,&kind,4}; return kaux_begin(NULL,&i); }
static int batch(u32 owner,const u32 *p,u32 n) { struct genl_info i={owner,p,n*4}; return kaux_batch(NULL,&i); }
static int end(u32 owner) { struct genl_info i={owner,NULL,0}; return kaux_end(NULL,&i); }
int main(void) {
  _Static_assert(sizeof(struct kaux_status)==160,"status ABI");
  u32 token[]={4,0x03020100,0x87868584,0x0b0a0908,0xfffefdfc};
  assert(begin(7,KAUX_KIND_TOKEN)==0);
  assert(begin(8,KAUX_KIND_POLICY)==-EBUSY);
  assert(batch(8,token,5)==-EPERM && end(8)==-EPERM);
  assert(batch(7,token,5)==0 && end(7)==0);
  assert(memcmp(g_token,token+1,16)==0);
  /* A kind beyond the last one is refused, and a refused BEGIN leaves no stream open. */
  assert(begin(7,KAUX_KIND_MAX+1u)==-EINVAL && end(7)==-EPERM);
  assert(memcmp(g_token,token+1,16)==0);
  assert(status_calls==0);
  /* Kind 2 was the hidden-names list. It is retired with the fork cleanup, so the kernel half
     must refuse it exactly like any kind it does not know. */
  u32 empty[]={0};
  assert(begin(7,2u)==0 && batch(7,empty,1)==-EINVAL && end(7)==-EPERM);
  assert(status_calls==0);
  policy_n=99;
  assert(begin(7,KAUX_KIND_POLICY)==0 && end(7)==0 && policy_n==0);
  u32 record[]={1,KAUX_OP_ADD,10123,64820,0xabcdef01,0x12345678,4,0x006b7061};
  assert(begin(7,KAUX_KIND_APKS)==0 && batch(7,record,8)==0 && end(7)==0);
  assert(seen_dev==64820 && seen_ino==0x12345678abcdef01ULL && last_failed==0);
  record[4]=record[5]=0;
  assert(begin(7,KAUX_KIND_APKS)==0 && batch(7,record,8)==0 && end(7)==-EIO && last_failed==1);
  assert(begin(7,KAUX_KIND_TOKEN)==0 && batch(7,token,4)==-EINVAL);
  assert(begin(8,KAUX_KIND_TOKEN)==0); // malformed owner stream was aborted
  jiffies += 6*HZ;
  assert(begin(9,KAUX_KIND_TOKEN)==0); // abandoned stream expires
  assert(batch(9,token,5)==0 && end(9)==0);
  assert(!g_stream_lock && !g_apply_lock);
  free(g_policy);
  puts("PASS production netlink handlers: token offsets, owner isolation, timeout, malformed batch, unknown kind, retired names kind, empty policy, 64-bit APK identity, negative END ack");
}
'''
file = out / 'probe.c'
file.write_text(shim + handlers + main)
assert handlers in file.read_text(), 'the tested handler source must be the production source'
subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-I'+str(root/'src/include'), str(file), '-o', str(out/'probe')], check=True)
subprocess.run([str(out/'probe')], check=True, timeout=10)

# Live host AF_UNIX control: /proc/net/unix reports the socket FD inode, not stat(path).
import socket
bound = out / "server.sock"
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(bound))
        listener.listen(1)
        fd = os.fstat(listener.fileno())
        node = os.stat(bound)
        rows = [line.split() for line in Path("/proc/net/unix").read_text().splitlines()]
        matching = [row for row in rows if len(row) == 8 and row[7] == str(bound) and int(row[3], 16) & 0x10000]
        assert len(matching) == 1 and int(matching[0][6]) == fd.st_ino
        assert (node.st_dev, node.st_ino) != (fd.st_dev, fd.st_ino)
finally:
    bound.unlink(missing_ok=True)
for major, minor in [(253, 52), (0, 17), (8, 257), (4095, 1048575)]:
    encoded = ((minor & 255) | (major << 8) | ((minor & ~255) << 12)) & 0xffffffff
    assert encoded == os.makedev(major, minor)
    assert (((encoded >> 8) & 4095), ((encoded & 255) | ((encoded >> 12) & 0xfff00))) == (major, minor)
print("PASS real /proc/net/unix sockfs inode differs from filesystem node; new_encode_dev round trips high minors")
