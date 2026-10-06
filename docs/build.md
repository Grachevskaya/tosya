# Build

Use Linux with CMake 3.22+, GNU make, Python 3, and the matching DDK kernel tree and compiler
for each KMI. The optional measurement tool below is the one thing in this tree that wants an
Android NDK.

Each KMI builds with its DDK compiler so that Clang CFI and shadow call stack
instrumentation match. Kbuild links the module and writes its objects into
`build/kmi/<KMI>`, a directory holding symlinks to `src/`.

## Package build

With all default DDKs under `/opt/ddk`:

```sh
cmake -S . -B build -DDDK_ROOT=/opt/ddk
cmake --build build -j8
```

Every KMI is built: android12-5.10, android13-5.10, android13-5.15, android14-5.15,
android14-6.1, android15-6.6, android16-6.12 and android17-6.18. The 5.x four used to sit
behind an option that was off by default; the guard that answers the reason for that is in
`src/patch.c`, and keeping them out of the build only meant they were never built.

Modules go to `build/ko`, and that is all this tree produces: there is no package, no
userspace loader and no boot script here any more. The repository with the userspace half
packages these modules and loads them.

There is no version metadata in this tree. The tag lookup and the versionCode arithmetic that
used to name the package, and the git plumbing that fed them, went with the packaging: the
module's version is the one the repository that packages it carries.

## Separate KMI builds

For environments with one DDK each, CMake and CI share `scripts/build-kmi.sh`:

| KMI | DDK compiler |
| --- | --- |
| android12-5.10 | clang-r416183b |
| android13-5.10 | clang-r450784e |
| android13-5.15 | clang-r450784e |
| android14-5.15 | clang-r487747c |
| android14-6.1 | clang-r487747c |
| android15-6.6 | clang-r510928 |
| android16-6.12 | clang-r536225 |
| android17-6.18 | clang-r584948c |

For example, run this inside the 6.1 build environment:

```sh
TOSYA_KBUILD_JOBS=8 bash scripts/build-kmi.sh \
  android14-6.1 clang-r487747c \
  build/kmi/android14-6.1 build/ko/android14-6.1_arm64_tosya.ko
```

Collect the desired modules in `build/ko`, then package them with the NDK:

```sh
cmake -S . -B build -DTOSYA_USE_PREBUILT_KO=ON
cmake --build build -j8
```

Prebuilt mode packages the files present in `build/ko`; keep that directory limited
to the intended candidate. `TOSYA_DEBUG=ON` enables permanent kernel diagnostics.
Normal packages leave it off; the `debug=1` module parameter enables them for 60 seconds.

## Loading

Install the zip through KernelSU and reboot. `customize.sh` selects the matching
KMI. `post-fs-data.sh` loads early; `service.sh` retries if needed . Both prefer `/data/adb/ksud insmod` and use the bundled loader only
when ksud is absent. Logs are in the installed module's `state/sync.log`.

For manual loading from a root shell on a boot without this module active:

```sh
/data/adb/ksud insmod /data/local/tmp/tosya.ko 'uid_tier=inline setuid_tier=inline'
```

Forcing the inline tiers disables fallback for that attempt. Normal package loading
uses automatic selection; check module status for the installed mechanisms and
errors. Published inline hooks remain loaded until reboot, so updating package
files does not replace the running module. A vermagic release-string difference
alone does not establish incompatibility, but the loader cannot repair incompatible
KMI structure layouts.

## uidbench

This optional measurement tool is not a package component. Cross-compile it and
run as an app uid with hiding rules:

```sh
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang" \
  -O2 -static -o uidbench src/tools/uidbench.c
```

It samples hidden, absent and unhooked cases in one round. Compare latency on a
controlled device workload; functional success alone does not establish a speedup.
