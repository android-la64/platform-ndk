#
# Copyright (C) 2016 The Android Open Source Project
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
"""Defines the NDK build system API.

Note: this isn't the ndk-build API, but the API for building the NDK itself.
"""
from __future__ import annotations

import shutil
import stat
import subprocess
import textwrap
import zipapp
from enum import Enum, auto, unique
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Iterator, List, Optional, Set

import ndk.paths
from ndk.autoconf import AutoconfBuilder
from ndk.cmake import CMakeBuilder
from ndk.hosts import Host


class ModuleValidateError(RuntimeError):
    """The error raised when module validation fails."""


@unique
class NoticeGroup(Enum):
    """An enum describing NOTICE file groupings.

    The NDK ships two NOTICE files: one for the toolchain, and one for
    everything else.
    """

    BASE = auto()
    TOOLCHAIN = auto()


class BuildContext:
    """Class containing build context information."""

    def __init__(
        self,
        out_dir: Path,
        dist_dir: Path,
        modules: List[Module],
        host: Host,
        build_number: int,
    ) -> None:
        self.out_dir = out_dir
        self.dist_dir = dist_dir
        self.modules = {m.name: m for m in modules}
        self.host = host
        self.build_number = build_number


class Module:
    """Base module type for the build system."""

    # pylint wrongly emits no-member if these don't have default values
    # https://github.com/PyCQA/pylint/issues/3167
    #
    # We override __getattribute__ to catch any uses of this value
    # uninitialized and raise an error.
    name: str = ""
    install_path: Path = Path()
    deps: Set[str] = set()

    def __getattribute__(self, name: str) -> Any:
        attr = super().__getattribute__(name)
        if name in ("name", "install_path") and attr == "":
            raise RuntimeError(f"Uninitialized use of {name}")
        return attr

    # Used to exclude a module from the build. If explicitly named it will
    # still be built, but it is not included by default.
    enabled = True

    # In most cases a module will have only one license file, so the common
    # interface is a single path, not a list. For the rare modules that have
    # multiple notice files (such as yasm), the notices property should be
    # overrided. By default this property will return `[self.notice]`.
    notice: Optional[Path] = None

    # Not all components need a notice (stub scripts, basic things like the
    # readme and changelog, etc), but this is opt-out.
    no_notice = False

    # Indicates which NOTICE file that should contain the license text for this
    # module. i.e. NoticeGroup.BASE will result in the license being included
    # in $NDK/NOTICE, whereas NoticeGroup.TOOLCHAIN will result in the license
    # text being included in NOTICE.toolchain.
    notice_group = NoticeGroup.BASE

    # Set to True if this module is merely a build convenience and not intented
    # to be shipped. For example, Platforms has its own build steps but is
    # shipped within the Toolchain module. If this value is set, the module's
    # install directory will not be within the NDK.
    intermediate_module = False

    def __init__(self) -> None:
        self.context: Optional[BuildContext] = None
        if self.notice is None:
            self.notice = self.default_notice_path()
        self.validate()

    @property
    def notices(self) -> Iterator[Path]:
        """Iterates over the notice files for this module."""
        if self.no_notice:
            return
        if self.notice is None:
            return
        yield self.notice

    # This can't actually be static because subclasses might use self, but for some
    # reason pylint doesn't know that in this case.
    def default_notice_path(self) -> Path | None:
        """Returns the path to the default notice for this module, if any."""
        return None

    def validate_error(self, msg: str) -> ModuleValidateError:
        """Creates a validation error for this module.

        Automatically includes the module name in the error string.

        Args:
            msg: Detailed error message.
        """
        return ModuleValidateError(f"{self.name}: {msg}")

    def validate(self) -> None:
        """Validates module config.

        Raises:
            ModuleValidateError: The module configuration is not valid.
        """
        if self.name is None:
            raise ModuleValidateError(f"{self.__class__} has no name")
        if self.install_path is None:
            raise self.validate_error("install_path property not set")
        if self.notice_group not in NoticeGroup:
            raise self.validate_error("invalid notice group")
        self.validate_notice()

    def validate_notice(self) -> None:
        """Validates the notice files of this module.

        Raises:
            ModuleValidateError: The module configuration is not valid.
        """
        if self.no_notice:
            return

        if not self.notices:
            raise self.validate_error("notice property not set")
        for notice in self.notices:
            if not notice.exists():
                raise self.validate_error(f"notice file {notice} does not exist")

    def get_dep(self, name: str) -> Module:
        """Returns the module object for the given dependency.

        Returns:
            The module object for the given dependency.

        Raises:
            KeyError: The given name does not match any of this module's
                dependencies.
        """
        if name not in self.deps:
            raise KeyError
        assert self.context is not None
        return self.context.modules[name]

    def get_build_host_install(self) -> Path:
        """Returns the module's install path for the current host.

        In a cross-compiling context (i.e. building the Windows NDK from
        Linux), this will return the install directory for the build OS rather
        than the target OS.

        Returns:
            This module's install path for the build host.
        """
        return self.get_install_path(Host.current())

    @property
    def out_dir(self) -> Path:
        """Base out directory for the current build."""
        assert self.context is not None
        return self.context.out_dir

    @property
    def dist_dir(self) -> Path:
        """Base dist directory for the current build."""
        assert self.context is not None
        return self.context.dist_dir

    @property
    def host(self) -> Host:
        """Host for the current build."""
        assert self.context is not None
        return self.context.host

    def build(self) -> None:
        """Builds the module.

        A module's dependencies are guaranteed to have been installed before
        its build begins.

        The build phase should not modify the install directory.
        """
        raise NotImplementedError(f"{self.name} didn't implement build().")

    def install(self) -> None:
        """Installs the module.

        Install happens after the module has been built.

        The install phase should only copy files, not create them. Compilation
        should happen in the build phase.
        """
        raise NotImplementedError(f"{self.name} didn't implement install().")

    def get_install_path(self, host: Optional[Host] = None) -> Path:
        """Returns the install path for the given module config.

        Args:
            host: The host to use for a host-specific install path.

        Raises:
            ValueError: This is an architecture-dependent module and no
                architecture was provided.
            RuntimeError: An architecture-independent module has non-unique
                install paths.
        """
        if host is None:
            host = self.host

        install_subdir = ndk.paths.expand_path(self.install_path, host)
        install_base = ndk.paths.get_install_path(self.out_dir, host)
        if self.intermediate_module:
            install_base = self.intermediate_out_dir / "install"
        return install_base / install_subdir

    @property
    def intermediate_out_dir(self) -> Path:
        """Path for intermediate outputs of this module."""
        return self.out_dir / self.host.value / self.name

    def __str__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        # The string representation of each module must be unique. This is true
        # both pre- and post-arch split.
        return hash(str(self))

    def __eq__(self, other: object) -> bool:
        # As with hash(), the str must be unique across all modules.
        return str(self) == str(other)

    @property
    def log_file(self) -> str:
        """Returns the basename of the log file for this module."""
        return f"{self.name}.log"

    def log_path(self, log_dir: Path) -> Path:
        """Returns the path to the log file for this module."""
        return log_dir / self.log_file


class AutoconfModule(Module):
    # Path to the source code
    src: Path
    env: Optional[Dict[str, str]] = None

    _builder: Optional[AutoconfBuilder] = None

    @property
    def builder(self) -> AutoconfBuilder:
        """Returns the lazily initialized builder for this module."""
        if self._builder is None:
            self._builder = AutoconfBuilder(
                self.src / "configure",
                self.intermediate_out_dir,
                self.host,
                additional_env=self.env,
            )
        return self._builder

    @property
    def configure_args(self) -> List[str]:
        return [
            "--disable-nls",
            "--disable-rpath",
        ]

    def build(self) -> None:
        self.builder.build(self.configure_args)

    def install(self) -> None:
        install_dir = self.get_install_path()
        install_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.builder.install_directory, install_dir, dirs_exist_ok=True)


class CMakeModule(Module):
    # Path to the source code
    src: Path
    _builder: Optional[CMakeBuilder] = None
    run_ctest: bool = False

    @property
    def builder(self) -> CMakeBuilder:
        """Returns the lazily initialized builder for this module."""
        if self._builder is None:
            self._builder = CMakeBuilder(
                self.src,
                self.intermediate_out_dir,
                self.host,
                additional_flags=self.flags,
                additional_ldflags=self.ldflags,
                additional_env=self.env,
                run_ctest=self.run_ctest,
            )
        return self._builder

    @property
    def env(self) -> Dict[str, str]:
        return {}

    @property
    def flags(self) -> List[str]:
        return []

    @property
    def ldflags(self) -> List[str]:
        return []

    @property
    def defines(self) -> Dict[str, str]:
        return {}

    def build(self) -> None:
        self.builder.build(self.defines)

    def install(self) -> None:
        install_dir = self.get_install_path()
        install_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.builder.install_directory, install_dir, dirs_exist_ok=True)


class PackageModule(Module):
    """A directory to be installed to the NDK.

    No transformation is performed on the installed directory.
    """

    #: The absolute path to the directory to be installed.
    src: Path

    def default_notice_path(self) -> Path:
        return self.src / "NOTICE"

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_path = self.get_install_path(self.host)
        install_directory(self.src, install_path)


class FileModule(Module):
    """A module that installs a single file to the NDK."""

    #: Path to the file to be installed.
    src: Path

    #: True if no notice file is needed for this module.
    no_notice = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_path = self.get_install_path()
        install_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.src, install_path)


class ScriptShortcutModule(Module):
    """A module that installs a shortcut to another script in the NDK.

    Some NDK tools are installed to a location other than the top of the NDK
    (as a result of the modular NDK effort), but we want to make them
    accessible from the top level because that is where they were Historically
    installed.
    """

    #: The path to the installed NDK script, relative to the top of the NDK.
    script: Path

    #: The file extension for the called script on Windows.
    windows_ext: str

    # These are all trivial shell scripts that we generated. No notice needed.
    no_notice = True

    disallow_windows_install_path_with_spaces: bool = False

    def validate(self) -> None:
        super().validate()

        if self.windows_ext is None:
            raise self.validate_error("ScriptShortcutModule requires windows_ext")

    def build(self) -> None:
        pass

    def install(self) -> None:
        if self.host.is_windows:
            self.make_cmd_helper()
        else:
            self.make_sh_helper()

    def make_cmd_helper(self) -> None:
        """Makes a .cmd helper script for Windows."""
        script = self.get_script_path().with_suffix(self.windows_ext)

        install_path = self.get_install_path().with_suffix(".cmd")
        text = "@echo off\n"
        if self.disallow_windows_install_path_with_spaces:
            text += textwrap.dedent(
                """\
                rem https://stackoverflow.com/a/29057742/632035
                for /f "tokens=2" %%a in ("%~dp0") do (
                    echo ERROR: NDK path cannot contain spaces
                    exit /b 1
                )
                """
            )
        text += f"%~dp0{PureWindowsPath(script)} %*"
        install_path.write_text(text)

    def make_sh_helper(self) -> None:
        """Makes a bash helper script for POSIX systems."""
        script = self.get_script_path()
        full_path = Path("$DIR") / script

        install_path = self.get_install_path()
        install_path.write_text(
            textwrap.dedent(
                f"""\
                #!/bin/sh
                DIR=$(cd "$(dirname "$0")" && pwd)
                "{full_path}" "$@"
                """
            )
        )
        mode = install_path.stat().st_mode
        install_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def get_script_path(self) -> Path:
        """Returns the installed path of the script."""
        return ndk.paths.expand_path(self.script, self.host)


class PythonPackage(Module):
    """A Python package that should be packaged for distribution.

    These are not installed within the NDK, but are packaged (as a source
    distribution) for archival on the build servers.

    These are used to archive the NDK's build and test tools so test artifacts
    may be regnenerated using only artifacts from the build server.
    """

    def default_notice_path(self) -> Path:
        # Assume there's a NOTICE file in the same directory as the setup.py.
        return self.install_path.parent / "NOTICE"

    def build(self) -> None:
        subprocess.check_call(
            ["python3", str(self.install_path), "sdist", "-d", self.out_dir],
            cwd=self.install_path.parent,
        )

    def install(self) -> None:
        pass


class PythonApplication(Module):
    """A PEP 441 Python Zip Application.

    https://peps.python.org/pep-0441/

    A Python Zip Application is a zipfile of a Python package with an entry point that
    is runnable by the Python interpreter. PythonApplication will create a the pyz
    application with its bundled dependencies and a launcher script that will invoke it
    using the NDK's bundled Python interpreter.
    """

    package: Path
    py_pkg_deps: list[Path] = []
    copy_to_python_path: list[Path] = []
    main: str

    def build(self) -> None:
        if self._staging.exists():
            shutil.rmtree(self._staging)
        self._staging.mkdir(parents=True)

        if self.package.is_file():
            shutil.copy(self.package, self._staging / self.package.name)
            (self._staging / "__init__.py").touch()
        else:
            shutil.copytree(self.package, self._staging / self.package.name)

        for path in self.copy_to_python_path:
            if path.is_file():
                shutil.copy(path, self._staging / path.name)
            else:
                shutil.copytree(path, self._staging / path.name)

        # Ideally this would be `pip install` (and it once was), but new
        # versions of pip don't support installing source packages without the
        # `wheel` package (https://github.com/pypa/pip/issues/8368). `wheel`
        # isn't part of the stdlib, and we can't fetch it from PyPI in CI, so we
        # can't use pip to install it any more.
        #
        # The risk is that we can't account for any quirks of the package. This
        # works for trivial packages, but anything with a complicated build
        # would not be installed correctly. We might detect too many or too few
        # sources, install packages to the wrong path, miss data files, etc.
        #
        # We might  be able to instead run the package's `setup.py install`
        # directly, but that only works if the packages stick with setup.py and
        # don't migrate to pyproject.toml, and I don't want to become a blocker
        # for that.
        for pkg_src in self.py_pkg_deps:
            shutil.copytree(pkg_src, self._staging / pkg_src.name)

        zipapp.create_archive(
            source=self._staging,
            target=self._pyz_build_location,
            main=self.main,
            filter=self.zipapp_file_filter,
        )

    @staticmethod
    def zipapp_file_filter(path: Path) -> bool:
        if ".git" in path.parts:
            return False
        if "__pycache__" in path.parts:
            return False
        if ".mypy_cache" in path.parts:
            return False
        if ".pytest_cache" in path.parts:
            return False
        if path.suffix in {".pyc", ".pyo"}:
            return False
        return True

    def install(self) -> None:
        install_path = self.get_install_path()
        install_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self._pyz_build_location, install_path)
        self.create_launcher()

    def create_launcher(self) -> None:
        if self.host is Host.Windows64:
            self.create_cmd_launcher()
        else:
            self.create_bash_launcher()

    def create_cmd_launcher(self) -> None:
        self.get_install_path().with_name(f"{self.name}.cmd").write_text(
            textwrap.dedent(
                f"""\
                @echo off
                setlocal
                set ANDROID_NDK_PYTHON=%~dp0..\\..\\..\\toolchains\\llvm\\prebuilt\\windows-x86_64\\python3\\python.exe
                set SHELL=cmd
                "%ANDROID_NDK_PYTHON%" -u "%~dp0{self.get_install_path().name}" %*
                """
            )
        )

    def create_bash_launcher(self) -> None:
        launcher = self.get_install_path().with_name(self.name)
        launcher.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                THIS_DIR=$(cd "$(dirname "$0")" && pwd)
                ANDROID_NDK_ROOT=$(cd "$THIS_DIR/../../.." && pwd)
                . "$ANDROID_NDK_ROOT/build/tools/ndk_bin_common.sh"
                "$ANDROID_NDK_PYTHON" "$THIS_DIR/{self.get_install_path().name}" "$@"
                """
            )
        )
        mode = launcher.stat().st_mode
        launcher.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    @property
    def _staging(self) -> Path:
        return self.intermediate_out_dir / self.name

    @property
    def _pyz_build_location(self) -> Path:
        return self.intermediate_out_dir / self.get_install_path().name


class LintModule(Module):
    def build(self) -> None:
        self.run()

    def install(self) -> None:
        pass

    def run(self) -> None:
        raise NotImplementedError


class MetaModule(Module):
    def build(self) -> None:
        pass

    def install(self) -> None:
        pass


def install_directory(src: Path, dst: Path) -> None:
    """Copies a directory to an install location, ignoring some file types.

    The destination will be removed prior to copying if it exists, ensuring a
    clean install.

    Some file types (currently python intermediates, editor swap files, git
    directories) will be removed from the install location.

    Args:
        src: Directory to install.
        dst: Install location. Will be removed prior to installation. The
            source directory will be copied *to* this path, not *into* this
            path.
    """
    # TODO: Remove the ignore patterns in favor of purging the install
    # directory after install, since not everything uses install_directory.
    #
    # We already do this to some extent with package_ndk, but we don't cover
    # all these file types, and we should also do this before packaging since
    # packaging only runs when a full NDK is built (fine for the build servers,
    # could potentially be wrong for local testing).
    if dst.exists():
        shutil.rmtree(dst)
    ignore_patterns = shutil.ignore_patterns("*.pyc", "*.pyo", "*.swp", "*.git*")
    shutil.copytree(src, dst, ignore=ignore_patterns)
