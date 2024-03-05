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
"""Tools for building test projects with CMake and ndk-build."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ndk.abis import Abi
from ndk.hosts import Host
from ndk.paths import ANDROID_DIR
from ndk.test.spec import BuildConfiguration, CMakeToolchainFile


class CMakeBuilder:
    """Builds a CMake project in the given test configuration."""

    def __init__(
        self,
        project: Path,
        ndk: Path,
        abi: Abi,
        min_sdk_version: int,
        toolchain_mode: CMakeToolchainFile,
        cmake_flags: list[str] | None = None,
    ) -> None:
        self.project = project
        self.ndk = ndk
        self.abi = abi
        self.min_sdk_version = min_sdk_version
        if toolchain_mode is CMakeToolchainFile.Legacy:
            self.toolchain_mode = "ON"
        else:
            self.toolchain_mode = "OFF"
        if cmake_flags is None:
            cmake_flags = []
        self.cmake_flags = cmake_flags

        # PythonBuildTest ensures that we're cd'd into the test out directory.
        self.out_dir = Path("build")

    @staticmethod
    def from_build_config(
        project: Path,
        ndk: Path,
        build_config: BuildConfiguration,
        cmake_build_flags: list[str] | None = None,
    ) -> CMakeBuilder:
        assert build_config.api is not None
        return CMakeBuilder(
            project,
            ndk,
            build_config.abi,
            build_config.api,
            build_config.toolchain_file,
            cmake_build_flags,
        )

    def build(self) -> str:
        """Configures and runs the build.

        stdout and stderr will be merged and returned if both stages succeed. If either
        fails, subprocess.CalledProcessError will be thrown and the stdout property will
        contain the merged output.
        """
        host = Host.current()
        if host == Host.Windows64:
            tag = "windows-x86"
        else:
            tag = f"{host.value}-x86"
        cmake = ANDROID_DIR / f"prebuilts/cmake/{tag}/bin/cmake"
        ninja = ANDROID_DIR / f"prebuilts/ninja/{tag}/ninja"
        if host == Host.Windows64:
            cmake = cmake.with_suffix(".exe")
            ninja = ninja.with_suffix(".exe")
        if self.out_dir.exists():
            shutil.rmtree(self.out_dir)
        self.out_dir.mkdir(parents=True)
        toolchain_file = self.ndk / "build/cmake/android.toolchain.cmake"
        cmd = [
            str(cmake),
            "-S",
            str(self.project),
            "-B",
            str(self.out_dir),
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}",
            f"-DANDROID_ABI={self.abi}",
            f"-DANDROID_PLATFORM=android-{self.min_sdk_version}",
            f"-DANDROID_USE_LEGACY_TOOLCHAIN_FILE={self.toolchain_mode}",
            "-GNinja",
            f"-DCMAKE_MAKE_PROGRAM={ninja}",
        ] + self.cmake_flags
        subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        return subprocess.run(
            [str(ninja), "-C", str(self.out_dir), "-v"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ).stdout


class NdkBuildBuilder:
    def __init__(
        self,
        project: Path,
        ndk: Path,
        abi: Abi,
        min_sdk_version: int,
        ndk_build_flags: list[str] | None = None,
    ) -> None:
        self.project = project
        self.ndk = ndk
        self.abi = abi
        self.min_sdk_version = min_sdk_version
        if ndk_build_flags is None:
            ndk_build_flags = []
        self.ndk_build_flags = ndk_build_flags
        self.out_dir = self.project / "libs" / self.abi

    @staticmethod
    def from_build_config(
        project: Path,
        ndk: Path,
        build_config: BuildConfiguration,
        ndk_build_flags: list[str] | None = None,
    ) -> NdkBuildBuilder:
        assert build_config.api is not None
        return NdkBuildBuilder(
            project, ndk, build_config.abi, build_config.api, ndk_build_flags
        )

    def build(self) -> str:
        """Runs the build.

        stdout and stderr will be merged and returned if the build succeeds. If it
        fails, subprocess.CalledProcessError will be thrown and the stdout property will
        contain the merged output.
        """
        ndk_build = self.ndk / "ndk-build"
        if Host.current() == Host.Windows64:
            ndk_build = ndk_build.with_suffix(".cmd")

        return subprocess.run(
            [
                str(ndk_build),
                "-C",
                str(self.project),
                "-B",
                "V=1",
                f"APP_ABI={self.abi}",
                f"APP_PLATFORM=android-{self.min_sdk_version}",
            ]
            + self.ndk_build_flags,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ).stdout
