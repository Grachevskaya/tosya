# Changelog

## 0.5.0

- The rename reaches everything it had left behind: include guards, host-test macros, the compiler
  flags in `src/Makefile`, the CMake variables and the CI, and the references to a tool this tree no
  longer holds now name the userspace half. Clang-tidy runs over the built module for the first time
  and found a real fault: the return of `tosya_inline_trampoline()` was stored and never checked, so a
  trampoline that failed to build would have been published.

- The module no longer carries a userspace half. `src/tools` is gone except `uidbench`, the timing
  instrument; the policy and the APK paths arrive over the same netlink family they always did, and a
  device that never pushes them hides nothing -- which is the honest state of a kernel half with no
  caller. A program that speaks those two blobs can live anywhere, and the package is a module zip with
  the ko files, the loader and the boot scripts.

- The policy query's fast half is inlined into the hooked wrappers and the walk stays out of line. A
  caller with no rules of its own is answered without a call, a frame or a second pointer: the snapshot
  the walk uses keeps its hot words first, so one RCU dereference serves both halves. Measured on
  android14-6.1: a hooked call went from a call into a 167-instruction function to about thirty inlined
  instructions, and the module got 264 bytes smaller.

- Nothing a build produces is published. A tag run reserves one message in the chat and builds every ko
  in parallel, each inside the image its kernel family is built in; every job hands its ko to that chat,
  because between jobs a public repository has no private channel -- an artifact or a cache can be
  downloaded by anyone who can read it. A second workflow, triggered when the build run finishes,
  collects those ko files, packs the module and writes it into the ninth line of the same message,
  taking the transport messages away again. Nothing is uploaded and nothing is relayed, so a compiled
  module exists only where it was sent. `module.prop` carries the identity the rest of the tree carries
  and no update URL, and the formatting check runs inside those same images, because a bare runner
  disagrees with them about the spacing clang-format writes inside braces.

- The module, its netlink family, its module parameters and every artifact are `tosya`. The KernelSU id
  changes with them, so an install of the old id is replaced rather than upgraded, and the tool and the
  module have to come from the same build. `KAUX_FAMILY_VERSION` is 5: the family name is how the tool
  finds the module and how the module recognises the tool, so a mismatch is a refusal in the open rather
  than two ends reading each other's command ids.

## 0.4.0

- Every hook mechanism is its own file, and which one is in place is a registry rather than a chain
  of `if`s. There are two questions -- how a uid with no processes is reported, and where an identity
  change is seen -- and for each one the mechanisms register an order and the runner walks them until
  one installs. The inline mechanism comes first for both: the uid queries are answered at
  `find_user()`, and the id change at `cap_task_fix_setuid()`, which the kernel hands both creds. The
  LSM hook and the syscall tables are the mechanisms behind them, and the order is data: moving one is
  a single number. `tosya.setuid_tier=` and `tosya.uid_tier=` force one mechanism, which tries
  only what it names, so a device can show each of them working on its own.

- The inline mechanism is a short entry trampoline, not a copy of the function. One aligned four-byte
  branch is published at the live entry -- through a single-word patch that stops the other CPUs, checks
  the word it is replacing and synchronizes instruction visibility -- and it jumps to a small trampoline
  built at load time that replays the displaced entry instructions and branches back into the native
  body. The rest of the function therefore keeps its own address, including its alternatives, exception
  tables and literals, and the relocator that whole-function copies needed is used only for the one or
  two displaced instructions, where anything it does not handle is still a refusal rather than a guess.
  A leading `BTI` or `PAC*SP` is left in place at the live entry and undone by a matching stub before
  the C handler runs, so the frame's signing stays balanced. When a direct branch cannot reach the
  trampoline, a private page is allocated near the image to hold a landing veneer, sealed read-only and
  executable before the entry is published, and a published entry keeps a module reference: a hooked
  module cannot be unloaded, which is permanent until reboot and what `hooks_remove()` says.

- A hidden uid is answered without asking the kernel a question it does not need. The policy is read
  first, and a hidden target is looked up as a replacement uid -- one that hashes into the *target's
  own* bucket, so the lookup walks the same chain the target's own lookup would -- and a replacement
  that has turned out to live is released and the answer is still `NULL`, never that unrelated user.
  The replacement is arithmetic, not a table or a search: for the additive hash every supported kernel
  uses (`__uidhashfn`; all six trees read, and none of them hashes uids with `hash_32`) the low bits of
  a uid are free, so the value is four instructions inside the reserved window, computed once per target
  when the policy is injected. A kernel that does hash uids differently is recognised and warned about,
  and its targets are still hidden -- with a value from the same window, which does not share their
  bucket. Hiding wins over sharing a bucket; a target is never left visible because a replacement could
  not be found.

- The status line names the mechanism in place for each of the two questions, by the name the
  registry gives it (`uid_tier`, `setuid_tier`: "inline find_user", "syscall tables", "inline
  cap_task_fix_setuid", "lsm: cap_task_fix_setuid", "syscall setters"), and is empty for a family that
  installed nothing. Before this, the two questions were reported through two different schemes and
  the inline path wrote the bare function name into the LSM field, so a device could not tell the
  inline hook from the LSM hook it replaced.

- The netlink family is `tosya`, not the generic `kaux`, and the family version is 4. Generic
  netlink families share one namespace and the tool resolves its family by name, so a generic name
  taken by another module would have left this one without a family of its own and pointed the tool at
  that other module. The version moved from 3 because the status structure changed size when the
  mechanism names replaced the LSM fields; a helper and a module of different versions cannot read
  each other's command ids, and the tool checks the status's magic, size and version before it
  believes anything in it.

- What that costs is measured rather than asserted. The answer never steers a branch: the two choices
  are `csel`s, and a hidden lookup and an *unhidden* lookup in the same bucket execute the same code
  with identical counts -- instruction count, data reads and writes, L1 misses and branch outcomes,
  taken on the host. Against a uid whose bucket is *empty* the residue is one walk of one entry: six
  instructions, one extra read, no extra cache line, no extra mispredict. The two failures this module
  used to have -- a branch on the answer, and a replacement uid the kernel takes longer to reject -- are
  gone; `uidbench` on a device remains the judge, and `docs/design.md` records what it measures.

- The status line says which mechanism is in place (`uid queries=inline find_user`,
  `setuid=inline cap_task_fix_setuid`) and, when none is, what the last one to fail said (through the
  `last_error` the tool already prints as `err=`).

- The registry is an explicit table, not a linker-collected section: `__start_`/`__stop_` symbols for a
  module's own section come out undefined on every KMI built here (kbuild with LTO), which would have
  been a module that does not load at all.

- Identity propagation preserves the task flags it does not own: the tag bits are moved with a
  compare-and-swap and a recheck, so a `TIF_` bit set by the scheduler or another module in the same
  word survives. Nothing is tagged at load when neither hook family installs, and the tier state is kept
  while a published inline hook is live.

- An empty configuration publishes an empty snapshot instead of a policy with no target, a filtered
  snapshot that ends up empty is handled the same way, and slot zero is a complete empty mask. A
  diagnostic read of a dentry after its path reference had been released is gone.

- APK updates are reconciled by inode across partial applications and lost replies: removals are
  confirmed before additions, uncertain records are retried, direct system-APK paths are accepted, and
  the rules are refreshed after a committed package or user database change. Watches are armed before
  the first synchronization attempt.

- The boot loader prefers an installed `ksud` and keeps the bundled loader for devices without it; KMI
  builds are shared between CMake and CI, worktrees and source exports are supported, and normal
  archives carry module template files only.

- The host test's `sched` shim closes its include guard, which it never did: harmless while every
  translation unit included it once, and two definitions of `current_fsuid` the moment the tag record
  moved into a file of its own.

## 0.3.3

- The tool reads the package database whichever form it is written in. Android 12 introduced the
  binary one (ABX) and `Xml.resolveSerializer()` picks between the two by the system property
  `persist.sys.binary_xml`, while reading sniffs the header -- so a device can carry either, and a
  device whose database is text used to get no rules at all, which is nothing hidden for anyone. One
  entry header hands out the same events for both forms, the readers live in their own units, and a
  file that is neither form is refused with the first bytes in the log rather than guessed at. Two
  things the text form needed besides a parser: the system flag, which that writer spells
  `publicFlags` where the binary one writes `flags`, and the shared user id, which was never read
  from a `<shared-user>` element at all.

- The manager hides itself under the xposed preset again. HMA-OSS writes itself into that preset in
  code and exports only the scanned half to its cache, and the generated table of written-in names
  had xposed empty: the generator collected quoted strings only, so the bare
  `BuildConfig.APP_PACKAGE_NAME` was dropped without a word. On a device that has run the app, where
  the cache answers, every caller that applies the preset saw the manager, while a scan of the same
  packages hid it. The generator resolves that name from the app's build script now and refuses to
  write a table at all when it meets an identifier it cannot resolve.

- A preset cache that cannot be parsed falls back to the older file instead of leaving the device
  with no presets and a full rescan of every installed apk, and a package that joins a shared user
  gets its app id back.

## 0.3.2

- A kernel where the setuid hook cannot be taken still learns who changes ids: the setters in both
  syscall tables are watched instead, which is the mechanism KernelSU uses for the same purpose.
  That is the state a vendor kernel with `CONFIG_TRIM_UNUSED_KSYMS=y` puts us in -- the symbol that
  moves a 6.12 LSM static call is not exported by any KMI this is built for, and a kernel that trims
  unused ksyms does not even have it in its image -- and the module used to say so and then hide
  nothing at all, because a process it never names has no rules. The status line says which of the
  two is in place (`setuid=<implementation>` or `setuid=syscall setters`), and the entry counts it
  reports include the setters, so that line reads ten of ten rather than four of four.

- The 6.12 LSM path takes the static call table's real size from kallsyms instead of trusting this
  build's `MAX_LSM_COUNT`, and enables the slot's own static key after taking it over; both are what
  KernelSU does as well.

## 0.3.1

- A hidden uid no longer answers measurably differently from a uid that does not exist. The lookup
  picked the replacement with a branch on the answer -- a predictor can learn that and a clock can
  see it -- and the value it picked was one the kernel takes several nanoseconds longer to reject
  than an ordinary uid. Both are fixed, and `uidbench` now judges its verdict against a control
  class (the same hidden uid measured twice) instead of the spread between two absent uids, which
  had been calling a real 13 ns difference not exploitable.

## 0.3.0

- An isolated child is named from the apk it opens, instead of from the openat hook that used to walk
  the dentry chain of every file it opened. Every app that has rules has its base.apk's `->open`
  replaced with a copy of the inode's `file_operations` that differs in that one member and carries
  the app id behind it, so the first open of its own code names the whole thread group. `openat` is
  gone from both syscall tables; nothing is looked up on the open path, no reference to the inode is
  taken, and the tables are put back at unload by finding each file again from its path.

- The id change is watched where the kernel commits it. The six setter wrappers in each syscall
  table are gone -- twelve entries, plus the compat numbers they were written with -- and
  `task_fix_setuid` is taken in the LSM hook list instead, chained into the implementation that was
  there (commoncap's on every kernel this is built for; SAFETY: SELinux does not implement it).
  Both creds are handed over, so nothing is sampled around a call, and 32-bit callers go through it
  too. A task that is named already is left alone, which is also what stops a process that changes
  ids repeatedly from being reported each time. The syscall tables keep the four uid lookup entries,
  native and compat, and nothing else.

- A 32-bit caller is no longer a way around the hiding. The compat entries are matched by the
  function that is in them -- the 64-bit implementation, or the compat wrapper under either of its
  names, in both spellings -- where the number used to decide, and the number this module carried
  for getpriority was 141 while the 32-bit table numbers it 96: the old code was patching getdents
  and _llseek. An entry that cannot be found is not hooked and says so.

- Text is written through the kernel's own fixmap window with a nofault copy, the way KernelSU's
  patcher does, instead of mapping the page again with vmap: the kernel builds the mapping, so no
  page protection has to be guessed. The write is proved before it happens -- the alias has to show
  the bytes that are at the target -- and the alias is derived from the kernel's own `vmemmap`, so a
  kernel whose VA size is not the one this module was built with is used rather than only refused.

- The physical address comes from the image offset first and the page table walk second. On a vendor
  kernel whose `struct mm_struct` is not the tree's, the walk answers with the wrong page; it is
  calibrated against the offset once at load and dropped if the two disagree.

- The protocol is defined once, in `include/kaux.h`, which the module and the tool both include. The
  retired apk command is gone, the staged commands are named for what they do, and
  `KAUX_CMD_STATUS` answers with what the module hooked: entry counts for both tables, apk inodes
  held and failures, whether the setuid hook was taken and from which implementation, the geometry
  the module was built for, and the last failure. The tool reads the running kernel's config to
  compare the geometry, and writes the summary into the module description -- the line KernelSU and
  Magisk show -- so a hook that is not installed is visible without a dmesg.

- The apk inode limit is 10000, the same as a user's app id space, and the staging buffers are 4 MiB
  and allocated on first use rather than at load. The tag and the wait bit are in separate bits now:
  the pending bit sat inside the tag field, which would have read as "still waiting" for a tag with
  the top bit set.

  a work profile queried its own user's uid and matched nothing. The helper reads
  /data/system/users and writes every pair once per user, each with the replacement its own bucket
  needs.

- A hidden target and one that was never configured now read the same addresses the same number of
  times, and read far less: the lookup takes the target's line and, from the mask of each probed
  slot, one word -- the caller's own. It used to read every word of every probed mask, ten loads per
  slot for a policy with six hundred callers. The masks are interned as well, one entry per distinct
  set of callers, so twenty-four thousand pairs keep a few hundred of them instead of one copy per
  slot. The same host benchmark over a sweep of four thousand targets went from 16.0 to 5.1 ns per
  query at that size; building the policy pays about a millisecond more for the interning.

- A name is never taken away by the code that marks a child as waiting or that closes the window:
  both move the flag with a compare-and-swap that leaves the tag field alone. A task that was named
  while either was in flight kept answering as one with no rules of its own before this. Kernel
  addresses also left the unconditional log lines -- they need the debug switch, which is what the
  module's own comment about dmesg asked for.

- The apk shadow is one table per file, never handed to another file, and the copy names this module
  as its owner. A table used to be given to the next replacement while the inode it was made for could
  still be read: that inode then dispatched into another filesystem's operations, an apk that came
  back after being dropped chained to this module's own open and called itself until the stack was
  gone, and a record was installed even when its path could not be stored, leaving a file that no
  unload could find again. The owner also makes an open file count against unload, so no file can
  still be holding a table when the module is given back.

- The inode whose open is replaced is held for as long as it is read, and only for that. A path
  resolves to a dentry, not to a committed inode: the package manager frees the inode it is replacing
  while the helper is still sending the new one, and reading its fields after that was a
  use-after-free -- on an uninstall, which is exactly when that happens.

- The app id is read from inside the uid, not from the whole number. An app of a secondary user
  (100000 + app) was compared against the isolated range as a whole uid, so it looked isolated and was
  never tagged: every app of that user was hidden from nothing, while the policy itself carried its
  pairs. A caller-0 pair ("hide from everyone") is honoured for a caller with no rules of its own as
  well -- the lookup used to answer zero for those before it ever read the target's line -- and the
  identity word is moved with a compare-and-swap, so a TIF_* bit the kernel sets in the same word is
  never lost.

- An apply is serialised: two uploads at once used to copy into the buffer while it was being parsed.
  The status line counts the apk inodes that are held from the table itself instead of adding deltas,
  so a drop for an entry this kernel never had can no longer take the number below zero, and a setuid
  hook whose slot could not be put back at unload says so instead of leaving a pointer into this
  module behind.

- The target table follows the number of targets instead of the worst collision on one line: a target
  goes into its own slot of its own line or of the lines that follow, so twenty-four thousand
  targets need 8192 lines (512 KB) where they needed 32768 (2 MB). A query reads one slot from
  each probed line and one word of its mask either way, which measures the same as before, and
  building the policy is slightly faster because the buffers a layout is built in are kept
  between applies. The staging buffers the kernel holds for an upload are 2 MiB rather than 4 --
  a policy cannot be larger than 512 KiB and an apk set than about 800 KiB -- so six megabytes
  of kernel memory are no longer held for nothing. The tool compares the apk set through hash
  sets instead of scanning the published list for every entry, which was up to a second of work
  on a device at the ten thousand apk limit, on every package event.

- The user ids are read on their own terms: the directory names under /data/system/users went
  through the parser written for uids, and that one rejects 0, so a device with a work profile
  wrote the work profile's pairs and dropped the primary user's -- the case above, still open.
  A listing that cannot be opened, stops half way or comes back empty is not a user set either:
  the previous policy is kept and the sync retries until it reads one (/data may still be
  encrypted at boot), and --once reports the failure instead of a success. A regression test
  covers user 0 beside a secondary user.

- The policy is published without a lock: the spinlock that was taken with interrupts off around it
  guarded a single pointer assignment, which is an atomic exchange by itself.
- The staged upload takes one, on the other hand: three commands write the same buffer and nothing
  serialised them. A second sender could only produce a policy whose CRC does not check out -- refused
  rather than half applied -- but a mutex keeps them from fighting over it.


- The presets a config applies follow the app line for line. The rules its own code computes
  (`canBeAddedIntoPreset`) were only partly copied here, so a package the app hides could be one this
  side did not count -- a uid hidden in userspace and still answered by the kernel. `sus_apps` by
  `com.termux` and the apk editor assets, `root_apps` by the viper, busybox, magisk and apatch names,
  the kernel manager libraries and the old `ACCESS_SUPERUSER` permission, `accessibility_apps` by its
  permission and never for a system app, `shizuku` by the provider it declares, `xposed` by the entry
  it carries or by being the app itself, `custom_rom` by the full overlay prefix list. A binary
  manifest keeps its strings in UTF-16, so one search looks for both forms: two checks that looked
  for bytes could never have matched on a device.
- Permissions are read from `/data/system/packages.xml` (`<perms>`) as well, and either source is
  enough.
- A regression test holds 25 cases, each naming the line of the app it stands for, and runs with the
  host tests in both rounds (plain and under ASan).

## 0.2.1

- A policy is uploaded in pages and only becomes live when its last page and its CRC check out, so a
  config with thousands of pairs is applied as one piece instead of being refused as too large.
- The netlink command ids moved with that, and the family version is 2: a helper and a module of
  different versions refuse each other instead of reading each other's commands.

## 0.2.0

- HMA and HMA-OSS each have their own config format and their own rules: the source that exists
  decides which one is in use, and each file is read by the parser written for it.
- HMA-OSS works as well as HMA: its config is read from
  /data/misc/hide_my_applist_*/config.json, and the preset cache it writes beside it says what each
  preset contains, so presets (which only the app can work out on the device) are applied too.
- The rule decision is the one HMA-OSS makes: the extra list, the opposite list, the applied
  templates, the applied presets, then whitelist mode. Rules from both tools are applied together.

## 0.1.3

- Config changes are noticed again. An event on a watched directory was taken for an install event
  and dropped, so a changed config was only picked up by the periodic pass -- and that pass is gone.

## 0.1.2

- The policy and the caller code table are sent to the kernel only when they changed, and only
  events for config.json itself count as a config change: an idle module no longer re-sends the
  same tables every few seconds.
- The sync runs on events, not on a timer. Watches that could not be created before the unlock are
  applied when it happens, and a push that did not land asks for one retry.
- The update record the module manager shows is text instead of the release page.

## 0.1.1

- The helper reads /data/system/packages.xml itself instead of asking "pm list packages -f -U"
  and walking /data/app, and installs arrive as inotify events on the first level of /data/app.
- The system flag comes from what that file records instead of MIUI's partition marker, so an
  updated preinstalled app stays a system app.

## 0.1.0

- First release. The module answers the app id (uid) of the packages HMA hides with the id of a
  real, unrelated, installed app, and the kernel refuses an id that a hidden package would be the
  only owner of.
