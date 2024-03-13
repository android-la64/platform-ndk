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
"""APIs for dealing with autoconf scripts."""
import multiprocessing
import os
import pprint
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import ContextManager, Dict, List, Optional

import ndk.ext.os
import ndk.paths
import ndk.toolchains
from ndk.hosts import Host, get_default_host

HOST_TRIPLE_MAP = {
    Host.Darwin: "x86_64-apple-darwin",
    Host.Linux: "x86_64-linux-gnu",
    Host.Windows64: "x86_64-w64-mingw32",
}


class AutoconfBuilder:
    """Builder for an autoconf project."""

    jobs_arg = f"-j{multiprocessing.cpu_count()}"

    toolchain: ndk.toolchains.Toolchain

    def __init__(
        self,
        configure_script: Path,
        build_dir: Path,
        host: Host,
        add_toolchain_to_path: bool = False,
        no_build_or_host: bool = False,
        no_strip: bool = False,
        additional_flags: Optional[list[str]] = None,
        additional_env: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initializes an autoconf builder.

        Args:
            configure_script: Path to the configure script.
            build_dir: Directory to use for building. If the directory exists,
            it will be deleted and recreated to ensure the build is correct.
            host: Host to be used for the --host argument (the
                cross-compilation target).
            add_toolchain_to_path: Adds the toolchain directory to the PATH
                when invoking configure and make. Needed for some projects that
                don't allow all tools to be passed via the environment.
            no_build_or_host: Don't pass --build or --host to configure.
            no_strip: Don't pass -s to compiler.
            additional_flags: Additional flags to pass to the compiler.
            additional_env: Additional environment to set, used during
                configure, build, and install.
        """
        self.configure_script = configure_script
        self.build_directory = build_dir
        self.host = host
        self.add_toolchain_to_path = add_toolchain_to_path
        self.no_build_or_host = no_build_or_host
        self.no_strip = no_strip
        self.additional_flags = additional_flags
        self.additional_env = additional_env

        self.working_directory = self.build_directory / "build"
        self.install_directory = self.build_directory / "install"

        self.toolchain = ndk.toolchains.ClangToolchain(self.host)

    @property
    def flags(self) -> List[str]:
        """Returns default cflags for the target."""
        # TODO: Are these the flags we want? These are what we've used
        # historically.
        flags = [
            "-Os",
            "-fomit-frame-pointer",
            # AC_CHECK_HEADERS fails if the compiler emits any warnings. We're
            # guaranteed to hit -Wunused-command-line-argument since autoconf
            # does a bad job with cflags/ldflags, so we need to pass all of the
            # flags all the time, but use -w since we won't be fixing any GDB
            # warnings anyway and failures caused by this don't actually appear
            # until much later in the build.
            "-w",
        ]
        if not self.host == Host.Darwin:
            flags.append("-fuse-ld=lld")
        if not self.no_strip:
            flags.append("-s")
        if self.additional_flags:
            flags.extend(self.additional_flags)
        return flags

    def cd(self) -> ContextManager[None]:
        """Context manager that moves into the working directory."""
        return ndk.ext.os.cd(self.working_directory)

    def _run(self, cmd: List[str], extra_env: Optional[Dict[str, str]] = None) -> None:
        """Runs and logs execution of a subprocess."""
        env = dict(extra_env) if extra_env is not None else {}
        if self.add_toolchain_to_path:
            paths = [str(p) for p in self.toolchain.bin_paths]
            paths.append(os.environ["PATH"])
            env["PATH"] = os.pathsep.join(paths)

        pp_cmd = " ".join([shlex.quote(arg) for arg in cmd])
        subproc_env = dict(os.environ)
        if env:
            subproc_env.update(env)
        if self.additional_env:
            subproc_env.update(self.additional_env)

        if subproc_env != dict(os.environ):
            pp_env = pprint.pformat(env, indent=4)
            print("Running: {} with env:\n{}".format(pp_cmd, pp_env))
        else:
            print("Running: {}".format(pp_cmd))

        subprocess.run(cmd, env=subproc_env, check=True)

    def clean(self) -> None:
        """Cleans output directory.

        If necessary, existing output directory will be removed. After
        removal, the inner directories (working directory, install directory,
        and toolchain directory) will be created.
        """
        if self.build_directory.exists():
            shutil.rmtree(self.build_directory)

        self.working_directory.mkdir(parents=True)
        self.install_directory.mkdir(parents=True)

    def configure(self, args: List[str]) -> None:
        """Invokes configure in the current directory with the given arguments.

        Args:
            args: List of arguments to be passed to configure. Does not need to
                include --prefix, --build, or --host. Those are set up
                automatically.
        """
        with self.cd():
            build_host_args: List[str]
            if self.no_build_or_host:
                build_host_args = []
            else:
                build_triple = HOST_TRIPLE_MAP[get_default_host()]
                host_triple = HOST_TRIPLE_MAP[self.host]
                build_host_args = [
                    f"--build={build_triple}",
                    f"--host={host_triple}",
                ]

            configure_args = (
                [
                    str(self.configure_script),
                    f"--prefix={self.install_directory}",
                ]
                + build_host_args
                + args
            )

            flags_str = " ".join(self.toolchain.flags + self.flags)
            cc = f"{self.toolchain.cc} {flags_str}"
            cxx = f"{self.toolchain.cxx} -stdlib=libc++ {flags_str}"

            configure_env: Dict[str, str] = {
                "CC": cc,
                "CXX": cxx,
                "LD": str(self.toolchain.ld),
                "AR": str(self.toolchain.ar),
                "AS": str(self.toolchain.asm),
                "RANLIB": str(self.toolchain.ranlib),
                "NM": str(self.toolchain.nm),
                "STRIP": str(self.toolchain.strip),
                "STRINGS": str(self.toolchain.strings),
            }
            if self.host.is_windows:
                configure_env["WINDRES"] = str(self.toolchain.rescomp)
                configure_env["RESCOMP"] = str(self.toolchain.rescomp)

            self._run(configure_args, configure_env)

    def make(self) -> None:
        """Builds the project."""
        with self.cd():
            self._run(["make", self.jobs_arg])

    def install(self) -> None:
        """Installs the project."""
        with self.cd():
            self._run(["make", self.jobs_arg, "install"])

    def build(self, configure_args: Optional[List[str]] = None) -> None:
        """Configures and builds an autoconf project.

        Args:
            configure_args: List of arguments to be passed to configure. Does
                not need to include --prefix, --build, or --host. Those are set
                up automatically.
        """
        self.clean()
        self.configure([] if configure_args is None else configure_args)
        self.make()
        self.install()
