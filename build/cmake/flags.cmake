# Copyright (C) 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file will be included directly by cmake. It is used to provide
# additional cflags / ldflags.

set(_ANDROID_NDK_INIT_CFLAGS)
set(_ANDROID_NDK_INIT_CFLAGS_DEBUG)
set(_ANDROID_NDK_INIT_CFLAGS_RELEASE)
set(_ANDROID_NDK_INIT_LDFLAGS)
set(_ANDROID_NDK_INIT_LDFLAGS_EXE)

# Generic flags.
string(APPEND _ANDROID_NDK_INIT_CFLAGS
  " -DANDROID"
  " -fdata-sections"
  " -ffunction-sections"
  " -funwind-tables"
  " -fstack-protector-strong"
  " -no-canonical-prefixes")

string(APPEND _ANDROID_NDK_INIT_CFLAGS_DEBUG " -fno-limit-debug-info")

# If we're using LLD we need to use a slower build-id algorithm to work around
# the old version of LLDB in Android Studio, which doesn't understand LLD's
# default hash ("fast").
#
# https://github.com/android/ndk/issues/885
string(APPEND _ANDROID_NDK_INIT_LDFLAGS " -Wl,--build-id=sha1")

if(CMAKE_SYSTEM_VERSION LESS 30)
  # https://github.com/android/ndk/issues/1196
  # https://github.com/android/ndk/issues/1589
  string(APPEND _ANDROID_NDK_INIT_LDFLAGS " -Wl,--no-rosegment")
endif()

string(APPEND _ANDROID_NDK_INIT_LDFLAGS " -Wl,--fatal-warnings")
string(APPEND _ANDROID_NDK_INIT_LDFLAGS_EXE " -Wl,--gc-sections")

# Toolchain and ABI specific flags.
if(CMAKE_ANDROID_ARCH_ABI STREQUAL x86 AND CMAKE_SYSTEM_VERSION LESS 24)
  # http://b.android.com/222239
  # http://b.android.com/220159 (internal http://b/31809417)
  # x86 devices have stack alignment issues.
  string(APPEND _ANDROID_NDK_INIT_CFLAGS " -mstackrealign")
endif()

string(APPEND _ANDROID_NDK_INIT_CFLAGS " -D_FORTIFY_SOURCE=2")

if(CMAKE_ANDROID_ARCH_ABI MATCHES "armeabi")
  # Clang does not set this up properly when using -fno-integrated-as.
  # https://github.com/android-ndk/ndk/issues/906
  string(APPEND _ANDROID_NDK_INIT_CFLAGS " -march=armv7-a")
  if(NOT CMAKE_ANDROID_ARM_MODE)
    string(APPEND _ANDROID_NDK_INIT_CFLAGS " -mthumb")
  endif()
  if(CMAKE_ANDROID_ARCH_ABI STREQUAL armeabi-v7a AND NOT CMAKE_ANDROID_ARM_NEON)
    string(APPEND _ANDROID_NDK_INIT_CFLAGS " -mfpu=vfpv3-d16")
  endif()
endif()

# CMake automatically forwards all compiler flags to the linker, and clang
# doesn't like having -Wa flags being used for linking. To prevent CMake from
# doing this would require meddling with the CMAKE_<LANG>_COMPILE_OBJECT rules,
# which would get quite messy.
string(APPEND _ANDROID_NDK_INIT_LDFLAGS " -Qunused-arguments")

if(ANDROID_DISABLE_FORMAT_STRING_CHECKS)
  string(APPEND _ANDROID_NDK_INIT_CFLAGS " -Wno-error=format-security")
else()
  string(APPEND _ANDROID_NDK_INIT_CFLAGS " -Wformat -Werror=format-security")
endif()

if(NOT ANDROID_ALLOW_UNDEFINED_SYMBOLS)
  string(APPEND _ANDROID_NDK_INIT_LDFLAGS " -Wl,--no-undefined")
endif()
