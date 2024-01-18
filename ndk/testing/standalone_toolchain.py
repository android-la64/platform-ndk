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
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import ndk.abis
import ndk.paths
from ndk.hosts import Host
from ndk.test.spec import BuildConfiguration


def logger() -> logging.Logger:
    return logging.getLogger(__name__)


def call_output(cmd: list[str], *args: Any, **kwargs: Any) -> tuple[int, Any]:
    logger().info("COMMAND: %s", " ".join(cmd))
    kwargs.update(
        {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
        }
    )
    with subprocess.Popen(cmd, *args, **kwargs) as proc:
        out, _ = proc.communicate()
        return proc.returncode, out


def get_python_executable(ndk_path: Path) -> Path:
    host = Host.current()
    python_dir = ndk_path / "toolchains/llvm/prebuilt" / host.tag / "python3"
    if host is Host.Windows64:
        return python_dir / "python.exe"
    return python_dir / "bin/python3"


def make_standalone_toolchain(
    ndk_path: Path, config: BuildConfiguration, extra_args: list[str], install_dir: Path
) -> tuple[bool, str]:
    make_standalone_toolchain_path = (
        ndk_path / "build/tools/make_standalone_toolchain.py"
    )

    arch = ndk.abis.abi_to_arch(config.abi)
    cmd = [
        str(get_python_executable(ndk_path)),
        str(make_standalone_toolchain_path),
        "--force",
        "--install-dir=" + str(install_dir),
        "--arch=" + arch,
        "--api={}".format(config.api),
    ] + extra_args

    rc, out = call_output(cmd)
    return rc == 0, out.decode("utf-8")


def test_standalone_toolchain(
    install_dir: Path, test_source: str, flags: list[str]
) -> tuple[bool, str]:
    compiler_name = "clang++"

    compiler = install_dir / "bin" / compiler_name
    cmd = [str(compiler), test_source, "-Wl,--no-undefined", "-Wl,--fatal-warnings"]
    cmd += flags
    if os.name == "nt":
        # The Windows equivalent of exec doesn't know file associations so it
        # tries to load the batch file as an executable. Invoke it with cmd.
        cmd = ["cmd", "/c"] + cmd
    rc, out = call_output(cmd)
    return rc == 0, out.decode("utf-8")


def run_test(
    ndk_path: Path,
    config: BuildConfiguration,
    test_source: str,
    extra_args: list[str],
    flags: list[str],
) -> tuple[bool, str]:
    # On Windows, the default directory for temporary files may have a different
    # (slow) configuration for security controls, indexing, etc. So we create
    # temporary directories directly in "out".
    install_dir = Path(
        (
            tempfile.mkdtemp(dir=ndk.paths.get_out_dir())
            if os.name == "nt"
            else tempfile.mkdtemp()
        )
    )
    try:
        success, out = make_standalone_toolchain(
            ndk_path, config, extra_args, install_dir
        )
        if not success:
            return success, out
        return test_standalone_toolchain(install_dir, test_source, flags)
    finally:
        # Try twice to delete the temporary directory, to work around
        # occasional "file in use" errors on Windows.
        try:
            shutil.rmtree(install_dir)
        except OSError:
            time.sleep(10)
            shutil.rmtree(install_dir)
