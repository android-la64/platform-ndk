# Changelog

Report issues to [GitHub].

For Android Studio issues, follow the docs on the [Android Studio site].

If you're a build system maintainer that needs to use the tools in the NDK
directly, see the [build system maintainers guide].

[GitHub]: https://github.com/android/ndk/issues
[Android Studio site]: http://tools.android.com/filing-bugs
[build system maintainers guide]: https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md

## Announcements

* KitKat (APIs 19 and 20) is no longer supported. The minimum OS supported by
  the NDK is Lollipop (API level 21). See [Issue 1751] for details.
* libc++ has been updated. The NDK's libc++ now comes directly from our LLVM
  toolchain, so every future LLVM update is also a libc++ update. Future
  changelogs will not explicitly mention libc++ updates.

[Issue 1751]: https://github.com/android/ndk/issues/1751

## r26d

* [Issue 1994]: Fixed ndk-gdb/ndk-lldb to use the correct path for
  make and other tools.

[Issue 1994]: https://github.com/android/ndk/issues/1994

## r26c

* Updated LLVM to clang-r487747e. See `AndroidVersion.txt` and
  `clang_source_info.md` in the toolchain directory for version information.
  * [Issue 1928]: Fixed Clang crash in instruction selection for 32-bit armv8
    floating point.
  * [Issue 1953]: armeabi-v7a libc++ libraries are once again built as thumb.

[Issue 1928]: https://github.com/android/ndk/issues/1928
[Issue 1953]: https://github.com/android/ndk/issues/1953

## r26b

* Updated LLVM to clang-r487747d. See `AndroidVersion.txt` and
  `clang_source_info.md` in the toolchain directory for version information.
  * This update was intended to be included in r26 RC 1. The original release
    noted these fixes in the changelog, but the new toolchain had not actually
    been included.
  * [Issue 1907]: HWASan linker will be used automatically for
    `minSdkVersion 34` or higher.
  * [Issue 1909]: Fixed ABI mismatch between function-multi-versioning and ifunc
    resolvers.
* [Issue 1938]: Fixed ndk-stack to use the correct path for llvm-symbolizer and
  other tools.

[Issue 1907]: https://github.com/android/ndk/issues/1907
[Issue 1909]: https://github.com/android/ndk/issues/1909
[Issue 1938]: https://github.com/android/ndk/issues/1938

## Changes

* Updated LLVM to clang-r487747c. See `AndroidVersion.txt` and
  `clang_source_info.md` in the toolchain directory for version information.
  * Clang now treats `-Wimplicit-function-declaration` as an error rather than a
    warning in C11 and newer. Clang's default C standard is 17, so this is a
    change in default behavior compared to older versions of Clang, but is the
    behavior defined by C99.

    If you encounter these errors when upgrading, you most likely forgot an
    `#include`. If you cannot (or do not want to) fix those issues, you can
    revert to the prior behavior with
    `-Wno-error=implicit-function-declaration`.

    C++ users are unaffected. This has never been allowed in C++.

    See https://reviews.llvm.org/D122983 for more details.
  * [Issue 1298]: Fixed seccomp error with ASan on x86_64 devices.
  * [Issue 1530]: Updated libc++ to match LLVM version.
  * [Issue 1565]: Fixed lldb ncurses issue with terminal database on Darwin.
  * [Issue 1677]: Fixed Clang crash in optimizer.
  * [Issue 1679]: Clang will now automatically enable ELF TLS for
    `minSdkVersion 29` or higher.
  * [Issue 1834]: Fixed Clang crash during SVE conversions.
  * [Issue 1860]: Fixed miscompilation affecting armv7.
  * [Issue 1861]: Fixed front end crash in Clang.
  * [Issue 1862]: Fixed Clang crash for aarch64 with `-Os`.
  * [Issue 1880]: Fixed crash in clang-format.
  * [Issue 1883]: Fixed crash when incorrectly using neon intrinsics.
* Version scripts that name public symbols that are not present in the library
  will now emit an error by default for ndk-build and the CMake toolchain file.
  Build failures caused by this error are likely a bug in your library or a
  mistake in the version script. To revert to the earlier behavior, pass
  `-DANDROID_ALLOW_UNDEFINED_VERSION_SCRIPT_SYMBOLS=ON` to CMake or set
  `LOCAL_ALLOW_UNDEFINED_VERSION_SCRIPT_SYMBOLS := true` in your `Android.mk`
  file. For other build systems, see the secion titled "Version script
  validation" in the [build system maintainers guide].
* [Issue 873]: Weak symbols for API additions is supported. Provide
  `__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__` as an option.
* [Issue 1400]: NDK paths with spaces will now be diagnosed by ndk-build on
  Windows. This has never been supported for any OS, but the error message
  wasn't previously working on Windows either.
* [Issue 1764]: Fixed Python 3 incompatibility when using `ndk-gdb` with `-f`.
* [Issue 1803]: Removed useless `strtoq` and `strtouq` from the libc stub
  libraries. These were never exposed in the header files, but could confuse
  some autoconf like systems.
* [Issue 1852]: Fixed ODR issue in linux/time.h.
* [Issue 1878]: Fixed incorrect definition of `WIFSTOPPED`.
* ndk-build now uses clang rather than clang++ when linking modules that do not
  have C++ sources. There should not be any observable behavior differences
  because ndk-build previously handled the C/C++ linking differences itself.
* ndk-build now delegates C++ stdlib linking to the Clang driver. It is unlikely
  that this will cause any observable behavior change, but any new behavior will
  more closely match CMake and other build systems.

[Issue 837]: https://github.com/android/ndk/issues/837
[Issue 1298]: https://github.com/android/ndk/issues/1298
[Issue 1400]: https://github.com/android/ndk/issues/1400
[Issue 1530]: https://github.com/android/ndk/issues/1530
[Issue 1565]: https://github.com/android/ndk/issues/1565
[Issue 1677]: https://github.com/android/ndk/issues/1677
[Issue 1679]: https://github.com/android/ndk/issues/1679
[Issue 1764]: https://github.com/android/ndk/issues/1764
[Issue 1803]: https://github.com/android/ndk/issues/1803
[Issue 1834]: https://github.com/android/ndk/issues/1834
[Issue 1852]: https://github.com/android/ndk/issues/1852
[Issue 1860]: https://github.com/android/ndk/issues/1860
[Issue 1861]: https://github.com/android/ndk/issues/1861
[Issue 1862]: https://github.com/android/ndk/issues/1862
[Issue 1878]: https://github.com/android/ndk/issues/1878
[Issue 1880]: https://github.com/android/ndk/issues/1880
[Issue 1883]: https://github.com/android/ndk/issues/1883

## Known Issues

This is not intended to be a comprehensive list of all outstanding bugs.

* [Issue 360]: `thread_local` variables with non-trivial destructors will cause
  segfaults if the containing library is `dlclose`ed. This was fixed in API 28,
  but code running on devices older than API 28 will need a workaround. The
  simplest fix is to **stop calling `dlclose`**. If you absolutely must continue
  calling `dlclose`, see the following table:

  |                   | Pre-API 23           |  APIs 23-27   | API 28+ |
  | ----------------- | -------------------- | ------------- | ------- |
  | No workarounds    | Works for static STL | Broken        | Works   |
  | `-Wl,-z,nodelete` | Works for static STL | Works         | Works   |
  | No `dlclose`      | Works                | Works         | Works   |

  If your code must run on devices older than M (API 23) and you cannot use the
  static STL (common), **the only fix is to not call `dlclose`**, or to stop
  using `thread_local` variables with non-trivial destructors.

  If your code does not need to run on devices older than API 23 you can link
  with `-Wl,-z,nodelete`, which instructs the linker to ignore `dlclose` for
  that library. You can backport this behavior by not calling `dlclose`.

  The fix in API 28 is the standardized inhibition of `dlclose`, so you can
  backport the fix to older versions by not calling `dlclose`.

* [Issue 988]: Exception handling when using ASan via wrap.sh can crash. To
  workaround this issue when using libc++_shared, ensure that your application's
  libc++_shared.so is in `LD_PRELOAD` in your `wrap.sh` as in the following
  example:

  ```bash
  #!/system/bin/sh
  HERE="$(cd "$(dirname "$0")" && pwd)"
  export ASAN_OPTIONS=log_to_syslog=false,allow_user_segv_handler=1
  ASAN_LIB=$(ls $HERE/libclang_rt.asan-*-android.so)
  if [ -f "$HERE/libc++_shared.so" ]; then
      # Workaround for https://github.com/android/ndk/issues/988.
      export LD_PRELOAD="$ASAN_LIB $HERE/libc++_shared.so"
  else
      export LD_PRELOAD="$ASAN_LIB"
  fi
  "$@"
   ```

  There is no known workaround for libc++_static.

  Note that because this is a platform bug rather than an NDK bug this cannot be
  fixed with an NDK update. This workaround will be necessary for code running
  on devices that do not contain the fix, and the bug has not been fixed even in
  the latest release of Android.

[Issue 360]: https://github.com/android/ndk/issues/360
[Issue 988]: https://github.com/android/ndk/issues/988
