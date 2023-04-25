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

[Issue 1751]: https://github.com/android/ndk/issues/1751

## Changes

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
* [Issue 1803]: Removed useless `strtoq` and `strtouq` from the libc stub
  libraries. These were never exposed in the header files, but could confuse
  some autoconf like systems.

[Issue 837]: https://github.com/android/ndk/issues/837
[Issue 1400]: https://github.com/android/ndk/issues/1400
[Issue 1803]: https://github.com/android/ndk/issues/1803

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
