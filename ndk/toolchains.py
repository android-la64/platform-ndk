#
# Copyright (C) 2019 The Android Open Source Project
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
#
"""APIs for accessing toolchains."""
import subprocess
from pathlib import Path
from typing import List

import ndk.paths
from ndk.hosts import Host, get_default_host

CLANG_VERSION = "clang-r522817"


HOST_TRIPLE_MAP = {
    Host.Darwin: "x86_64-apple-darwin",
    Host.Linux: "x86_64-linux-gnu",
    Host.Windows64: "x86_64-w64-mingw32",
}


class DarwinSdk:
    """The Darwin SDK."""

    MACOSX_TARGET = "10.9"

    def __init__(self) -> None:
        self.mac_sdk_path = self._get_sdk_path()
        self.linker_version = self._get_ld_version()

        self.ar = self.sdk_tool("ar")
        self.asm = self.sdk_tool("as")
        self.ld = self.sdk_tool("ld")
        self.nm = self.sdk_tool("nm")
        self.ranlib = self.sdk_tool("ranlib")
        self.strings = self.sdk_tool("strings")
        self.strip = self.sdk_tool("strip")

    @property
    def flags(self) -> List[str]:
        """The default flags to be used with the SDK."""
        return [
            f"-mmacosx-version-min={self.MACOSX_TARGET}",
            f"-DMACOSX_DEPLOYMENT_TARGET={self.MACOSX_TARGET}",
            f"-isysroot{self.mac_sdk_path}",
            f"-Wl,-syslibroot,{self.mac_sdk_path}",
            # https://stackoverflow.com/a/60958449/632035
            # Our Clang is not built to handle old linkers by default, so if we
            # do not configure this explicitly it may attempt to use flags that
            # are not supported by the version of the Darwin linker installed on
            # the build machine.
            f"-mlinker-version={self.linker_version}",
        ]

    @staticmethod
    def sdk_tool(name: str) -> Path:
        """Returns the path to the given SDK tool."""
        proc_result = subprocess.run(
            ["xcrun", "--find", name],
            stdout=subprocess.PIPE,
            check=True,
            encoding="utf-8",
        )
        return Path(proc_result.stdout.strip())

    @staticmethod
    def _get_sdk_path() -> Path:
        """Gets the path to the Mac SDK."""
        proc_result = subprocess.run(
            ["xcrun", "--show-sdk-path"],
            stdout=subprocess.PIPE,
            check=True,
            encoding="utf-8",
        )
        return Path(proc_result.stdout.strip())

    @staticmethod
    def _get_ld_version() -> str:
        """Gets the version of the system linker."""
        proc_result = subprocess.run(
            ["ld", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            encoding="utf-8",
        )
        output = proc_result.stderr.strip().splitlines()[0]
        # Example first line: @(#)PROGRAM:ld  PROJECT:ld64-409.12
        return output.rsplit("-", 1)[-1]


class Toolchain:
    """A compiler toolchain.

    Describes the directories, executables, and default flags needed to use a
    toolchain.
    """

    def __init__(self, target: Host, host: Host = get_default_host()) -> None:
        if host.is_windows:
            raise NotImplementedError
        self.host = host
        self.target = target

        if self.target == Host.Darwin:
            self.darwin_sdk = DarwinSdk()

    @property
    def ar(self) -> Path:
        """The path to the archiver."""
        raise NotImplementedError

    @property
    def asm(self) -> Path:
        """The path to the assembler."""
        raise NotImplementedError

    @property
    def bin_paths(self) -> List[Path]:
        """The path to the toolchain binary directories for use with PATH."""
        raise NotImplementedError

    @property
    def cc(self) -> Path:
        """The path to the C compiler."""
        raise NotImplementedError

    @property
    def cxx(self) -> Path:
        """The path to the C++ compiler."""
        raise NotImplementedError

    @property
    def flags(self) -> List[str]:
        """The default flags to be used with the compiler."""
        raise NotImplementedError

    @property
    def ld(self) -> Path:
        """The path to the linker."""
        raise NotImplementedError

    @property
    def nm(self) -> Path:
        """The path to nm."""
        raise NotImplementedError

    @property
    def path(self) -> Path:
        """The path to the top level toolchain directory."""
        raise NotImplementedError

    @property
    def ranlib(self) -> Path:
        """The path to ranlib."""
        raise NotImplementedError

    @property
    def rescomp(self) -> Path:
        """The path to the resource compiler."""
        raise NotImplementedError

    @property
    def strip(self) -> Path:
        """The path to strip."""
        raise NotImplementedError

    @property
    def strings(self) -> Path:
        """The path to strings."""
        raise NotImplementedError


class Sysroot:
    """A sysroot for the target platform."""

    def __init__(self, target: Host) -> None:
        self.target = target

    @property
    def bin_paths(self) -> List[Path]:
        """The path to the toolchain binary directories for use with PATH."""
        return [self.path / "bin"]

    @property
    def lib_dirs(self) -> List[Path]:
        """Returns the paths to the GCC library directories for the given host.

        The GCC library directory contains libgcc and other compiler runtime
        libraries. These may be split across multiple directories.
        """
        lib_dirs = [
            self.path
            / {
                Host.Darwin: "lib/gcc/i686-apple-darwin11/4.2.1",
                Host.Linux: "lib/gcc/x86_64-linux/4.8.3",
                Host.Windows64: "lib/gcc/x86_64-w64-mingw32/4.8.3",
            }[self.target]
        ]
        if self.target != Host.Darwin:
            lib_dirs.append(self.path / self.triple / "lib64")
        return lib_dirs

    @property
    def path(self) -> Path:
        """Returns the path to the top level toolchain directory."""
        if self.target == Host.Darwin:
            return (
                ndk.paths.ANDROID_DIR
                / "prebuilts/gcc/darwin-x86/host/i686-apple-darwin-4.2.1"
            )
        if self.target == Host.Linux:
            return (
                ndk.paths.ANDROID_DIR
                / "prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8"
            )
        return (
            ndk.paths.ANDROID_DIR
            / "prebuilts/gcc/linux-x86/host/x86_64-w64-mingw32-4.8"
        )

    @property
    def sysroot(self) -> Path:
        """The path to the GCC sysroot."""
        if self.target == Host.Linux:
            return self.path / "sysroot"
        return self.path / self.triple

    @property
    def triple(self) -> str:
        """Returns the GCC triple for the host toolchain."""
        return {
            Host.Darwin: "x86_64-apple-darwin11",
            Host.Linux: "x86_64-linux",
            Host.Windows64: "x86_64-w64-mingw32",
        }[self.target]


class ClangToolchain(Toolchain):
    """A Clang compiler toolchain."""

    def __init__(self, target: Host, host: Host = get_default_host()) -> None:
        super().__init__(target, host=host)
        self.sysroot = Sysroot(target)

    @staticmethod
    def path_for_host(host: Host) -> Path:
        """Returns the path to the Clang directory for the given host."""
        host_tag = {
            Host.Darwin: "darwin-x86",
            Host.Linux: "linux-x86",
            Host.Windows64: "windows-x86",
        }[host]
        return ndk.paths.ANDROID_DIR / "prebuilts/clang/host" / host_tag / CLANG_VERSION

    @property
    def path(self) -> Path:
        """Returns the path to the top level toolchain directory."""
        return self.path_for_host(self.host)

    def clang_tool(self, tool_name: str) -> Path:
        """Returns the path to the Clang tool for the build host."""
        return self.path / "bin" / tool_name

    @property
    def ar(self) -> Path:
        """The path to the archiver."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.ar
        return self.clang_tool("llvm-ar")

    @property
    def asm(self) -> Path:
        """The path to the assembler."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.asm
        return self.cc

    @property
    def bin_paths(self) -> List[Path]:
        """The path to the toolchain binary directories for use with PATH."""
        return [self.path / "bin"]

    @property
    def cc(self) -> Path:
        return self.clang_tool("clang")

    @property
    def cxx(self) -> Path:
        return self.clang_tool("clang++")

    @property
    def lib_dirs(self) -> List[Path]:
        lib_dirs = self.sysroot.lib_dirs
        # libc++ library path. Static only for Windows.
        if self.target.is_windows:
            lib_dirs.append(self.path_for_host(self.target) / "lib64")
        else:
            lib_dirs.append(self.path / "lib64")
        return lib_dirs

    @property
    def flags(self) -> List[str]:
        host_triple = HOST_TRIPLE_MAP[self.target]
        flags = [
            f"--target={host_triple}",
        ]

        if self.target.is_windows:
            flags.append("-I" + str(self.path_for_host(self.target) / "include/c++/v1"))

        if self.target == Host.Darwin:
            flags.extend(self.darwin_sdk.flags)
            flags.append(f"-L{self.path}/lib")
        else:
            flags.append(f"--sysroot={self.sysroot.sysroot}")

            for lib_dir in self.lib_dirs:
                # Both -L and -B because Clang only searches for CRT
                # objects in -B directories.
                flags.extend(
                    [
                        f"-L{lib_dir}",
                        f"-B{lib_dir}",
                    ]
                )

        return flags

    @property
    def ld(self) -> Path:
        """The path to the linker."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.ld
        return self.clang_tool("ld.lld")

    @property
    def nm(self) -> Path:
        """The path to nm."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.nm
        return self.clang_tool("llvm-nm")

    @property
    def ranlib(self) -> Path:
        """The path to ranlib."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.ranlib
        return self.clang_tool("llvm-ranlib")

    @property
    def rescomp(self) -> Path:
        """The path to the resource compiler."""
        if not self.target.is_windows:
            raise NotImplementedError
        return self.clang_tool("llvm-windres")

    @property
    def strip(self) -> Path:
        """The path to strip."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.strip
        return self.clang_tool("llvm-strip")

    @property
    def strings(self) -> Path:
        """The path to strings."""
        if self.target == Host.Darwin:
            return self.darwin_sdk.strings
        return self.clang_tool("llvm-strings")
