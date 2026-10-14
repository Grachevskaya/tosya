#!/usr/bin/env python3
"""Compile and exercise the production policy.c RCU name table under sanitizers."""
from pathlib import Path
import subprocess
import os
root = Path(__file__).resolve().parents[1]
source = (root / 'src/policy.c').read_text()
start = source.index('struct tosya_names {')
end = source.index('struct apply_pair {', start)
production = source[start:end]
assert all(symbol in production for symbol in ('tosya_names_apply(', 'tosya_names_trie_match(', 'tosya_trie_free('))
out = root / '.scratch/tests/names'
out.mkdir(parents=True, exist_ok=True)
shim = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint8_t u8;
#define __rcu
#define GFP_KERNEL 0
#define kzalloc(n,f) calloc(1,n)
#define kvzalloc(n,f) calloc(1,n)
#define kvcalloc(n,s,f) calloc(n,s)
#define kfree(p) free(p)
#define kvfree(p) free(p)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
#define rcu_replace_pointer(var,value,condition) (__extension__({ __typeof__(var) before = (var); (var) = (value); before; }))
#define WRITE_ONCE(p,v) ((p)=(v))
#define synchronize_rcu() ((void)0)
'''
main = r'''
static u32 add(u32 *rec, u32 at, const char *name, u32 seed) {
    u32 len = (u32)strlen(name);
    rec[at++] = len;
    rec[at++] = seed;
    memcpy(&rec[at], name, len);
    return at + (len+3u)/4u;
}
static int match(const char *name, u32 expected) {
    u32 seed = 3;
    u32 len = tosya_names_trie_match((const u8 *)name, (u32)strlen(name), &seed);
    return (expected == UINT32_MAX) ? (len == 0 && seed == 3) :
        (len == strlen(name) && seed == expected);
}
int main(void) {
    u32 words[100] = {0}, at = 0, generation;
    at = add(words,at,"com.app.one",0);
    at = add(words,at,"com.app.two",UINT32_MAX);
    at = add(words,at,"com.app",9);
    at = add(words,at,"org.app.one",8);
    assert(tosya_names_apply(words,at)==0);
    assert(match("com.app.one",0));
    { u32 seed=0; assert(tosya_names_trie_match((u8*)"com.app.two",11,&seed)==11 && seed==UINT32_MAX); }
    assert(match("com.app",9) && match("org.app.one",8));
    assert(match("com.app.three",UINT32_MAX) && match("com.ap",UINT32_MAX));
    { u32 broken[16]={0}; u32 n=add(broken,0,"bad/name",1);
      generation=g_names_gen;
      assert(tosya_names_apply(broken,n)==-EINVAL && g_names_gen==generation);
      assert(match("com.app.one",0)); }
    for (int i=0;i<20;i++) {
      memset(words,0,sizeof words);
      at=add(words,0,i%2?"new.name":"other.name",(u32)i);
      assert(tosya_names_apply(words,at)==0);
      assert(match(i%2?"new.name":"other.name",(u32)i));
      assert(match("com.app.one",UINT32_MAX));
    }
    { char record[256]; assert(tosya_names_copy(record,sizeof record)>0); }
    assert(tosya_names_apply(NULL,0)==0);
    assert(match("new.name",UINT32_MAX) && tosya_names_bytes()==0);
    tosya_names_free();
    puts("PASS actual policy.c trie: sibling/prefix lookup, zero and max seeds, malformed update rollback, repeated RCU replacement, empty clear, ASan/UBSan");
}
'''
file = out / 'probe.c'
file.write_text(shim + production + main)
assert production in file.read_text()
subprocess.run([os.environ.get('CC','clang'),'-std=gnu11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(file),'-o',str(out/'probe')],check=True)
subprocess.run([str(out/'probe')],check=True,timeout=20,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
