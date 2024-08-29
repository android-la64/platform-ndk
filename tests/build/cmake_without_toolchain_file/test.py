#
# Copyright (C) 2024 The Android Open Source Project
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
"""Tests that using CMake without the toolchain file doesn't fail for trivial cases.

This isn't something we expect to work well, but it is something people use, so we at
least verify that the most trivial of builds succeed.
"""
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from ndk.hosts import Host
from ndk.paths import ANDROID_DIR
from ndk.test.spec import BuildConfiguration


def find_cmake_and_ninja() -> tuple[Path, Path]:
    host = Host.current()
    if host is Host.Windows64:
        tag = "windows-x86"
    else:
        tag = f"{host.value}-x86"
    return (
        ANDROID_DIR / f"prebuilts/cmake/{tag}/bin/cmake",
        ANDROID_DIR / f"prebuilts/ninja/{tag}/ninja",
    )


def run_test(ndk_path: str, config: BuildConfiguration) -> tuple[bool, str | None]:
    cmake, ninja = find_cmake_and_ninja()
    with TemporaryDirectory() as build_dir:
        try:
            subprocess.run(
                [
                    cmake,
                    "-B",
                    build_dir,
                    "-S",
                    ".",
                    f"-DCMAKE_ANDROID_NDK={ndk_path.as_posix()}",
                    "-DCMAKE_SYSTEM_NAME=Android",
                    f"-DCMAKE_SYSTEM_VERSION={config.api}",
                    f"-DCMAKE_ANDROID_ARCH_ABI={config.abi}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    "-G",
                    "Ninja",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            subprocess.run(
                [cmake, "--build", build_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except subprocess.CalledProcessError as ex:
            return False, f"Build failed:\n{ex.output}"
    return True, None
