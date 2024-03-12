#
# Copyright (C) 2015 The Android Open Source Project
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
"""Build test cases."""

import importlib.util
import logging
import multiprocessing
import os
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from importlib.abc import Loader
from pathlib import Path
from subprocess import CompletedProcess
from typing import List, Optional, Tuple

import ndk.ansi
import ndk.ext.os
import ndk.ext.subprocess
import ndk.hosts
import ndk.ndkbuild
import ndk.paths
from ndk.abis import Abi
from ndk.cmake import find_cmake, find_ninja
from ndk.test.config import TestConfig
from ndk.test.filters import TestFilter
from ndk.test.result import Failure, Skipped, Success, TestResult
from ndk.test.spec import BuildConfiguration, CMakeToolchainFile


def logger() -> logging.Logger:
    """Return the logger for this module."""
    return logging.getLogger(__name__)


def _get_jobs_args() -> List[str]:
    cpus = multiprocessing.cpu_count()
    return [f"-j{cpus}", f"-l{cpus}"]


def _prep_build_dir(src_dir: Path, out_dir: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(src_dir, out_dir, ignore=shutil.ignore_patterns("__pycache__"))


class Test(ABC):
    def __init__(
        self, name: str, test_dir: Path, config: BuildConfiguration, ndk_path: Path
    ) -> None:
        self.name = name
        self.test_dir = test_dir
        self.config = config
        self.ndk_path = ndk_path
        self.config = self.config.with_api(self.determine_api_level_for_config())

    @abstractmethod
    def determine_api_level_for_config(self) -> int: ...

    def get_test_config(self) -> TestConfig:
        return TestConfig.from_test_dir(self.test_dir)

    def run(
        self, obj_dir: Path, dist_dir: Path, test_filters: TestFilter
    ) -> Tuple[TestResult, List["Test"]]:
        raise NotImplementedError

    def is_negative_test(self) -> bool:
        raise NotImplementedError

    def check_broken(self) -> tuple[None, None] | tuple[str, str]:
        return self.get_test_config().build_broken(self)

    def check_unsupported(self) -> Optional[str]:
        return self.get_test_config().build_unsupported(self)

    def get_build_dir(self, out_dir: Path) -> Path:
        raise NotImplementedError

    def __str__(self) -> str:
        return f"{self.name} [{self.config}]"


class BuildTest(Test):
    def __init__(
        self, name: str, test_dir: Path, config: BuildConfiguration, ndk_path: Path
    ) -> None:
        super().__init__(name, test_dir, config, ndk_path)

        if self.api is None:
            raise ValueError

    @property
    def abi(self) -> Abi:
        return self.config.abi

    @property
    def api(self) -> Optional[int]:
        return self.config.api

    @property
    def ndk_build_flags(self) -> List[str]:
        flags = self.config.get_extra_ndk_build_flags()
        return flags + self.get_extra_ndk_build_flags()

    @property
    def cmake_flags(self) -> List[str]:
        flags = self.config.get_extra_cmake_flags()
        return flags + self.get_extra_cmake_flags()

    def make_build_result(self, proc: CompletedProcess[str]) -> TestResult:
        if proc.returncode == 0:
            return Success(self)
        return Failure(
            self, f"Test build failed: {shlex.join(proc.args)}:\n{proc.stdout}"
        )

    def verify_no_cruft_in_dist(
        self, dist_dir: Path, build_cmd: list[str]
    ) -> Optional[Failure[None]]:
        bad_files = []
        for path in ndk.paths.walk(dist_dir, directories=False):
            if path.suffix == ".a":
                bad_files.append(str(path))
        if bad_files:
            files = "\n".join(bad_files)
            return Failure(
                self,
                f"Found unexpected files in test dist directory. Build command was: "
                f"{shlex.join(build_cmd)}\n{files}",
            )
        return None

    def run(
        self, obj_dir: Path, dist_dir: Path, _test_filters: TestFilter
    ) -> Tuple[TestResult, List[Test]]:
        raise NotImplementedError

    def check_broken(self) -> tuple[None, None] | tuple[str, str]:
        return self.get_test_config().build_broken(self)

    def check_unsupported(self) -> Optional[str]:
        return self.get_test_config().build_unsupported(self)

    def is_negative_test(self) -> bool:
        return self.get_test_config().is_negative_test()

    def get_extra_cmake_flags(self) -> List[str]:
        return self.get_test_config().extra_cmake_flags()

    def get_extra_ndk_build_flags(self) -> List[str]:
        return self.get_test_config().extra_ndk_build_flags()

    def get_overridden_runtime_minsdkversion(self) -> int | None:
        return self.get_test_config().override_runtime_minsdkversion(self)


class PythonBuildTest(BuildTest):
    """A test that is implemented by test.py.

    A test.py test has a test.py file in its root directory. This module
    contains a run_test function which returns a Tuple[bool, Optional[str]] of
    the success status and, if applicable, an error message and takes the
    following kwargs:

    ndk_path: The path to the NDK under test.
    abi: The ABI being tested.
    api: The minSdkVersion being tested.
    linker: The LinkerOption option being.

    The test source directory will be copied into the test build directory for
    the given build configuration. The working directory will automatically be
    set to the root of the copied source test directory.
    """

    def __init__(
        self, name: str, test_dir: Path, config: BuildConfiguration, ndk_path: Path
    ) -> None:
        super().__init__(name, test_dir, config, ndk_path)

        if self.abi not in ndk.abis.ALL_ABIS:
            raise ValueError("{} is not a valid ABI".format(self.abi))

        try:
            assert self.api is not None
            int(self.api)
        except ValueError as ex:
            raise ValueError(f"{self.api} is not a valid API number") from ex

    def determine_api_level_for_config(self) -> int:
        return ndk.abis.min_api_for_abi(self.config.abi)

    def get_build_dir(self, out_dir: Path) -> Path:
        return out_dir / str(self.config) / "test.py" / self.name

    def run(
        self, obj_dir: Path, _dist_dir: Path, _test_filters: TestFilter
    ) -> Tuple[TestResult, List[Test]]:
        build_dir = self.get_build_dir(obj_dir)
        logger().info("Building test: %s", self.name)
        _prep_build_dir(self.test_dir, build_dir)
        with ndk.ext.os.cd(build_dir):
            spec = importlib.util.spec_from_file_location("test", "test.py")
            if spec is None or spec.loader is None:
                path = build_dir / "test.py"
                raise RuntimeError(f"Could not import {path}")
            module = importlib.util.module_from_spec(spec)
            # https://github.com/python/typeshed/issues/2793
            assert isinstance(spec.loader, Loader)
            spec.loader.exec_module(module)
            success, failure_message = module.run_test(self.ndk_path, self.config)
            if success:
                return Success(self), []
            return Failure(self, failure_message), []


class ShellBuildTest(BuildTest):
    def determine_api_level_for_config(self) -> int:
        return ndk.abis.min_api_for_abi(self.config.abi)

    def get_build_dir(self, out_dir: Path) -> Path:
        return out_dir / str(self.config) / "build.sh" / self.name

    def run(
        self, obj_dir: Path, _dist_dir: Path, _test_filters: TestFilter
    ) -> Tuple[TestResult, List[Test]]:
        build_dir = self.get_build_dir(obj_dir)
        logger().info("Building test: %s", self.name)
        if os.name == "nt":
            reason = "build.sh tests are not supported on Windows"
            return Skipped(self, reason), []
        assert self.api is not None
        result = _run_build_sh_test(
            self,
            build_dir,
            self.test_dir,
            self.ndk_path,
            self.ndk_build_flags,
            self.abi,
            self.api,
        )
        return result, []


def _run_build_sh_test(
    test: ShellBuildTest,
    build_dir: Path,
    test_dir: Path,
    ndk_path: Path,
    ndk_build_flags: List[str],
    abi: Abi,
    platform: int,
) -> TestResult:
    _prep_build_dir(test_dir, build_dir)
    with ndk.ext.os.cd(build_dir):
        build_cmd = ["bash", "build.sh"] + _get_jobs_args() + ndk_build_flags
        test_env = dict(os.environ)
        test_env["NDK"] = str(ndk_path)
        if abi is not None:
            test_env["APP_ABI"] = abi
        test_env["APP_PLATFORM"] = f"android-{platform}"
        rc, out = ndk.ext.subprocess.call_output(
            build_cmd, env=test_env, encoding="utf-8"
        )
        if rc == 0:
            return Success(test)
        return Failure(test, out)


def _platform_from_application_mk(test_dir: Path) -> Optional[int]:
    """Determine target API level from a test's Application.mk.

    Args:
        test_dir: Directory of the test to read.

    Returns:
        Integer portion of APP_PLATFORM if found, else None.

    Raises:
        ValueError: Found an unexpected value for APP_PLATFORM.
    """
    application_mk = test_dir / "jni" / "Application.mk"
    if not application_mk.exists():
        return None

    with application_mk.open(encoding="utf-8") as application_mk_file:
        for line in application_mk_file:
            if line.startswith("APP_PLATFORM"):
                _, platform_str = line.split(":=")
                break
        else:
            return None

    platform_str = platform_str.strip()
    if not platform_str.startswith("android-"):
        raise ValueError(platform_str)

    _, api_level_str = platform_str.split("-")
    return int(api_level_str)


def _get_or_infer_app_platform(
    overridden_runtime_minsdkversion: int | None,
    test_dir: Path,
    abi: Abi,
) -> int:
    """Determines the platform level to use for a test using ndk-build.

    Choose the platform level from, in order of preference:
    1. The value forced by the test_config.py using override_runtime_minsdkversion.
    2. APP_PLATFORM from jni/Application.mk.
    3. Default value for the target ABI.

    Args:
        overridden_runtime_minsdkversion: The test's forced runtime minSdkVersion. Might
            differ from the build API level. This is rare (probably only static
            executables).
        test_dir: The directory containing the ndk-build project.
        abi: The ABI being targeted.

    Returns:
        The platform version the test should build against.
    """
    if overridden_runtime_minsdkversion is not None:
        return overridden_runtime_minsdkversion

    minimum_version = ndk.abis.min_api_for_abi(abi)
    platform_from_application_mk = _platform_from_application_mk(test_dir)
    if platform_from_application_mk is not None:
        if platform_from_application_mk >= minimum_version:
            return platform_from_application_mk

    return minimum_version


class NdkBuildTest(BuildTest):
    def __init__(
        self,
        name: str,
        test_dir: Path,
        config: BuildConfiguration,
        ndk_path: Path,
        dist: bool,
    ) -> None:
        super().__init__(name, test_dir, config, ndk_path)
        self.dist = dist

    def determine_api_level_for_config(self) -> int:
        return _get_or_infer_app_platform(
            self.get_overridden_runtime_minsdkversion(),
            self.test_dir,
            self.config.abi,
        )

    def get_dist_dir(self, obj_dir: Path, dist_dir: Path) -> Path:
        if self.dist:
            return self.get_build_dir(dist_dir)
        return self.get_build_dir(obj_dir) / "dist"

    def get_build_dir(self, out_dir: Path) -> Path:
        return out_dir / str(self.config) / "ndk-build" / self.name

    def run(
        self, obj_dir: Path, dist_dir: Path, _test_filters: TestFilter
    ) -> Tuple[TestResult, List[Test]]:
        logger().info("Building test: %s", self.name)
        obj_dir = self.get_build_dir(obj_dir)
        dist_dir = self.get_dist_dir(obj_dir, dist_dir)
        assert self.api is not None
        proc = _run_ndk_build_test(
            obj_dir,
            dist_dir,
            self.test_dir,
            self.ndk_path,
            self.ndk_build_flags,
            self.abi,
        )
        if (failure := self.verify_no_cruft_in_dist(dist_dir, proc.args)) is not None:
            return failure, []
        return self.make_build_result(proc), []


def _run_ndk_build_test(
    obj_dir: Path,
    dist_dir: Path,
    test_dir: Path,
    ndk_path: Path,
    ndk_build_flags: List[str],
    abi: Abi,
) -> CompletedProcess[str]:
    _prep_build_dir(test_dir, obj_dir)
    with ndk.ext.os.cd(obj_dir):
        args = [
            f"APP_ABI={abi}",
            f"NDK_LIBS_OUT={dist_dir}",
        ] + _get_jobs_args()
        return ndk.ndkbuild.build(ndk_path, args + ndk_build_flags)


class CMakeBuildTest(BuildTest):
    def __init__(
        self,
        name: str,
        test_dir: Path,
        config: BuildConfiguration,
        ndk_path: Path,
        dist: bool,
    ) -> None:
        super().__init__(name, test_dir, config, ndk_path)
        self.dist = dist

    def determine_api_level_for_config(self) -> int:
        return _get_or_infer_app_platform(
            self.get_overridden_runtime_minsdkversion(),
            self.test_dir,
            self.config.abi,
        )

    def get_dist_dir(self, obj_dir: Path, dist_dir: Path) -> Path:
        if self.dist:
            return self.get_build_dir(dist_dir)
        return self.get_build_dir(obj_dir) / "dist"

    def get_build_dir(self, out_dir: Path) -> Path:
        return out_dir / str(self.config) / "cmake" / self.name

    def run(
        self, obj_dir: Path, dist_dir: Path, _test_filters: TestFilter
    ) -> Tuple[TestResult, List[Test]]:
        obj_dir = self.get_build_dir(obj_dir)
        dist_dir = self.get_dist_dir(obj_dir, dist_dir)
        logger().info("Building test: %s", self.name)
        assert self.api is not None
        proc = _run_cmake_build_test(
            obj_dir,
            dist_dir,
            self.test_dir,
            self.ndk_path,
            self.cmake_flags,
            self.abi,
            self.config.toolchain_file == CMakeToolchainFile.Legacy,
        )
        if (failure := self.verify_no_cruft_in_dist(dist_dir, proc.args)) is not None:
            return failure, []
        return self.make_build_result(proc), []


def _run_cmake_build_test(
    obj_dir: Path,
    dist_dir: Path,
    test_dir: Path,
    ndk_path: Path,
    cmake_flags: List[str],
    abi: str,
    use_legacy_toolchain_file: bool,
) -> CompletedProcess[str]:
    _prep_build_dir(test_dir, obj_dir)

    cmake_bin = find_cmake()
    ninja_bin = find_ninja()

    toolchain_file = ndk_path / "build" / "cmake" / "android.toolchain.cmake"
    abi_obj_dir = obj_dir / abi
    abi_lib_dir = dist_dir / abi
    args = [
        f"-H{obj_dir}",
        f"-B{abi_obj_dir}",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}",
        f"-DANDROID_ABI={abi}",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={abi_lib_dir}",
        f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={abi_lib_dir}",
        "-GNinja",
        f"-DCMAKE_MAKE_PROGRAM={ninja_bin}",
    ]
    if use_legacy_toolchain_file:
        args.append("-DANDROID_USE_LEGACY_TOOLCHAIN_FILE=ON")
    else:
        args.append("-DANDROID_USE_LEGACY_TOOLCHAIN_FILE=OFF")
    proc = subprocess.run(
        [str(cmake_bin)] + args + cmake_flags,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        return proc
    return subprocess.run(
        [str(cmake_bin), "--build", str(abi_obj_dir), "--"] + _get_jobs_args(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
