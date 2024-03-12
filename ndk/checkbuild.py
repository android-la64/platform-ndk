#!/usr/bin/env python3
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
"""Builds the NDK.

Cleans old build artifacts, configures the required environment, determines
build goals, and invokes the build scripts.
"""
import argparse
import collections
import contextlib
import copy
import inspect
import json
import logging
import multiprocessing
import os
import re
import shutil
import site
import stat
import subprocess
import sys
import textwrap
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    Iterable,
    Iterator,
    List,
    Set,
    TextIO,
    Tuple,
)

import ndk.abis
import ndk.ansi
import ndk.archive
import ndk.autoconf
import ndk.builds
import ndk.cmake
import ndk.config
import ndk.deps
import ndk.notify
import ndk.paths
import ndk.test.builder
import ndk.test.printers
import ndk.test.spec
import ndk.timer
import ndk.ui
import ndk.workqueue
from ndk.abis import ALL_ABIS, Abi
from ndk.crtobjectbuilder import CrtObjectBuilder
from ndk.hosts import Host
from ndk.paths import ANDROID_DIR, NDK_DIR, PREBUILT_SYSROOT
from ndk.platforms import ALL_API_LEVELS, API_LEVEL_ALIASES, MAX_API_LEVEL
from ndk.toolchains import CLANG_VERSION, ClangToolchain

from .ndkversionheadergenerator import NdkVersionHeaderGenerator
from .pythonenv import ensure_python_environment


def get_version_string(build_number: int) -> str:
    """Returns the version string for the current build."""
    return f"{ndk.config.major}.{ndk.config.hotfix}.{build_number}"


def purge_unwanted_files(ndk_dir: Path) -> None:
    """Removes unwanted files from the NDK install path."""

    for path in ndk.paths.walk(ndk_dir, directories=False):
        if path.suffix == ".pyc":
            path.unlink()
        elif path.name == "Android.bp":
            path.unlink()


def make_symlink(src: Path, dest: Path) -> None:
    src.unlink(missing_ok=True)
    if dest.is_absolute():
        src.symlink_to(Path(os.path.relpath(dest, src.parent)))
    else:
        src.symlink_to(dest)


def create_stub_entry_point(path: Path) -> None:
    """Creates a stub "application" for the app bundle.

    App bundles must have at least one entry point in the Contents/MacOS
    directory. We don't have a single entry point, and none of our executables
    are useful if moved, so just put a welcome script in place that explains
    that.
    """
    path.parent.mkdir(exist_ok=True, parents=True)
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            echo "The Android NDK is installed to the Contents/NDK directory of this application bundle."
            """
        )
    )
    path.chmod(0o755)


def create_plist(plist: Path, version: str, entry_point_name: str) -> None:
    """Populates the NDK plist at the given location."""
    plist.write_text(
        textwrap.dedent(
            f"""\
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>CFBundleName</key>
                <string>Android NDK</string>
                <key>CFBundleDisplayName</key>
                <string>Android NDK</string>
                <key>CFBundleIdentifier</key>
                <string>com.android.ndk</string>
                <key>CFBundleVersion</key>
                <string>{version}</string>
                <key>CFBundlePackageType</key>
                <string>APPL</string>
                <key>CFBundleExecutable</key>
                <string>{entry_point_name}</string>
            </dict>
            </plist>
            """
        )
    )


def create_signer_metadata(package_dir: Path) -> None:
    """Populates the _codesign metadata directory for the ADRT signer.

    Args:
        package_dir: Path to the root of the directory that will be zipped for
                     the signer.
    """
    metadata_dir = package_dir / "_codesign"
    metadata_dir.mkdir()

    # This directory can optionally contain a few pieces of metadata:
    #
    # filelist: For any jar files that need to be unpacked and signed. We have
    # none.
    #
    # entitlements.xml: Defines any entitlements we need. No known, currently.
    #
    # volumename: The volume name for the DMG that the signer will create.
    #
    # See http://go/studio-signer for more information.

    volumename_file = metadata_dir / "volumename"
    volumename_file.write_text(f"Android NDK {ndk.config.release}")


def make_app_bundle(
    worker: ndk.workqueue.Worker,
    zip_path: Path,
    ndk_dir: Path,
    build_number: int,
    build_dir: Path,
) -> None:
    """Builds a macOS App Bundle of the NDK.

    The NDK is distributed in two forms on macOS: as a app bundle and in the
    traditional layout. The traditional layout is needed by the SDK because AGP
    and Studio expect the NDK to be contained one directory down in the
    archive, which is not compatible with macOS bundles. The app bundle is
    needed on macOS because we rely on rpaths, and executables using rpaths are
    blocked by Gate Keeper as of macOS Catalina (10.15), except for references
    within the same bundle.

    Information on the macOS bundle format can be found at
    https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html.

    Args:
        zip_path: The desired file path of the resultant zip file (without the
                  extension).
        ndk_dir: The path to the NDK being bundled.
        build_dir: The path to the top level build directory.
    """
    worker.status = "Packaging MacOS App Bundle"
    package_dir = build_dir / "bundle"
    app_directory_name = f"AndroidNDK{build_number}.app"
    bundle_dir = package_dir / app_directory_name
    if package_dir.exists():
        shutil.rmtree(package_dir)

    contents_dir = bundle_dir / "Contents"
    entry_point_name = "ndk"
    create_stub_entry_point(contents_dir / "MacOS" / entry_point_name)

    bundled_ndk = contents_dir / "NDK"
    shutil.copytree(ndk_dir, bundled_ndk)

    plist = contents_dir / "Info.plist"
    create_plist(plist, get_version_string(build_number), entry_point_name)

    shutil.copy2(ndk_dir / "source.properties", package_dir / "source.properties")
    create_signer_metadata(package_dir)
    ndk.archive.make_zip(
        zip_path,
        package_dir,
        [p.name for p in package_dir.iterdir()],
        preserve_symlinks=True,
    )


def make_brtar(
    worker: ndk.workqueue.Worker,
    base_name: Path,
    root_dir: Path,
    base_dir: Path,
    preserve_symlinks: bool,
) -> None:
    worker.status = "Packaging .tar.br"
    ndk.archive.make_brtar(
        base_name, root_dir, base_dir, preserve_symlinks=preserve_symlinks
    )


def make_zip(
    worker: ndk.workqueue.Worker,
    base_name: Path,
    root_dir: Path,
    paths: List[str],
    preserve_symlinks: bool,
) -> None:
    worker.status = "Packaging .zip"
    ndk.archive.make_zip(
        base_name, root_dir, paths, preserve_symlinks=preserve_symlinks
    )


def package_ndk(
    ndk_dir: Path, out_dir: Path, dist_dir: Path, host: Host, build_number: int
) -> Path:
    """Packages the built NDK for distribution.

    Args:
        ndk_dir: Path to the built NDK.
        out_dir: Path to use for constructing any intermediate outputs.
        dist_dir: Path to place the built package in.
        host: Host the given NDK was built for.
        build_number: Build number to use in the package name.
    """
    package_name = f"android-ndk-{build_number}-{host.tag}"
    package_path = dist_dir / package_name

    purge_unwanted_files(ndk_dir)

    workqueue: ndk.workqueue.WorkQueue = ndk.workqueue.WorkQueue()
    try:
        if host == Host.Darwin:
            workqueue.add_task(
                make_app_bundle,
                dist_dir / f"android-ndk-{build_number}-app-bundle",
                ndk_dir,
                build_number,
                out_dir,
            )
        workqueue.add_task(
            make_brtar,
            package_path,
            ndk_dir.parent,
            Path(ndk_dir.name),
            preserve_symlinks=(host != Host.Windows64),
        )
        workqueue.add_task(
            make_zip,
            package_path,
            ndk_dir.parent,
            [ndk_dir.name],
            preserve_symlinks=(host != Host.Windows64),
        )
        ndk.ui.finish_workqueue_with_ui(workqueue, ndk.ui.get_build_progress_ui)
    finally:
        workqueue.terminate()
        workqueue.join()
    # TODO: Treat the .tar.br archive as authoritative and return its path.
    return package_path.with_suffix(".zip")


def build_ndk_tests(out_dir: Path, dist_dir: Path, args: argparse.Namespace) -> bool:
    """Builds the NDK tests.

    Args:
        out_dir: Build output directory.
        dist_dir: Preserved artifact directory.
        args: Parsed command line arguments.

    Returns:
        True if all tests pass, else False.
    """
    # The packaging step extracts all the modules to a known directory for
    # packaging. This directory is not cleaned up after packaging, so we can
    # reuse that for testing.
    ndk_dir = ndk.paths.get_install_path(out_dir)
    test_src_dir = ndk.paths.ndk_path("tests")
    test_out_dir = out_dir / "tests"

    site.addsitedir(str(ndk_dir / "python-packages"))

    test_options = ndk.test.spec.TestOptions(
        test_src_dir,
        ndk_dir,
        test_out_dir,
        clean=True,
        package_path=(
            Path(dist_dir).joinpath("ndk-tests") if args.package_tests else None
        ),
    )

    printer = ndk.test.printers.StdoutPrinter()

    test_spec = ndk.test.spec.TestSpec.load(ndk.paths.ndk_path("qa_config.json"))
    builder = ndk.test.builder.TestBuilder(test_spec, test_options, printer)

    report = builder.build()
    printer.print_summary(report)

    if not report.successful:
        # Write out the result to logs/build_error.log so we can find the
        # failure easily on the build server.
        log_path = dist_dir / "logs" / "build_error.log"
        with log_path.open("a", encoding="utf-8") as error_log:
            error_log_printer = ndk.test.printers.FilePrinter(error_log)
            error_log_printer.print_summary(report)

    return report.successful


def install_file(file_name: str, src_dir: Path, dst_dir: Path) -> None:
    src_file = src_dir / file_name
    dst_file = dst_dir / file_name

    print("Copying {} to {}...".format(src_file, dst_file))
    if src_file.is_dir():
        _install_dir(src_file, dst_file)
    elif src_file.is_symlink():
        _install_symlink(src_file, dst_file)
    else:
        _install_file(src_file, dst_file)


def _install_dir(src_dir: Path, dst_dir: Path) -> None:
    parent_dir = dst_dir.parent
    if not parent_dir.exists():
        parent_dir.mkdir(parents=True)
    shutil.copytree(src_dir, dst_dir, symlinks=True)


def _install_symlink(src_file: Path, dst_file: Path) -> None:
    dirname = dst_file.parent
    if not dirname.exists():
        dirname.mkdir(parents=True)
    link_target = os.readlink(src_file)
    os.symlink(link_target, dst_file)


def _install_file(src_file: Path, dst_file: Path) -> None:
    dirname = dst_file.parent
    if not dirname.exists():
        dirname.mkdir(parents=True)
    # copy2 is just copy followed by copystat (preserves file metadata).
    shutil.copy2(src_file, dst_file)


ALL_MODULE_TYPES: list[type[ndk.builds.Module]] = []


def register(module_class: type[ndk.builds.Module]) -> type[ndk.builds.Module]:
    ALL_MODULE_TYPES.append(module_class)
    return module_class


@register
class Clang(ndk.builds.Module):
    name = "clang"
    install_path = Path("toolchains/llvm/prebuilt/{host}")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    @property
    def notices(self) -> Iterator[Path]:
        # TODO: Inject Host before this runs and remove this hack.
        # Just skip the license checking for dev builds. Without this the build
        # will fail because there's only a clang-dev for one of the hosts.
        if CLANG_VERSION == "clang-dev":
            return
        for host in Host:
            yield ClangToolchain.path_for_host(host) / "NOTICE"

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_path = self.get_install_path()
        bin_dir = install_path / "bin"

        if install_path.exists():
            shutil.rmtree(install_path)
        if not install_path.parent.exists():
            install_path.parent.mkdir(parents=True)
        shutil.copytree(
            ClangToolchain.path_for_host(self.host),
            install_path,
            symlinks=not self.host.is_windows,
        )

        # The prebuilt Linux Clangs include a bazel file for some other users.
        # We don't need or test this interface so we shouldn't ship it.
        if self.host is Host.Linux:
            (install_path / "BUILD.bazel").unlink()

        # clang-4053586 was patched in the prebuilts directory to add the
        # libc++ includes. These are almost certainly a different revision than
        # the NDK libc++, and may contain local changes that the NDK's don't
        # and vice versa. Best to just remove them for the time being since
        # that returns to the previous behavior.
        # https://github.com/android-ndk/ndk/issues/564#issuecomment-342307128
        shutil.rmtree(install_path / "include")

        if self.host is Host.Linux:
            # The Linux toolchain wraps the compiler to inject some behavior
            # for the platform. They aren't used for every platform and we want
            # consistent behavior across platforms, and we also don't want the
            # extra cost they incur (fork/exec is cheap, but CreateProcess is
            # expensive), so remove them.
            assert set(bin_dir.glob("*.real")) == {
                bin_dir / "clang++.real",
                bin_dir / "clang.real",
                bin_dir / "clang-tidy.real",
            }
            (bin_dir / "clang++.real").unlink()
            (bin_dir / "clang++").unlink()
            (bin_dir / "clang-cl").unlink()
            (bin_dir / "clang-tidy").unlink()
            (bin_dir / "clang.real").rename(bin_dir / "clang")
            (bin_dir / "clang-tidy.real").rename(bin_dir / "clang-tidy")
            make_symlink(bin_dir / "clang++", Path("clang"))

        bin_ext = ".exe" if self.host.is_windows else ""
        if self.host.is_windows:
            # Remove LLD duplicates. We only need ld.lld. For non-Windows these
            # are all symlinks so we can keep them (and *need* to keep lld
            # since that's the real binary).
            # http://b/74250510
            (bin_dir / f"ld64.lld{bin_ext}").unlink()
            (bin_dir / f"lld{bin_ext}").unlink()
            (bin_dir / f"lld-link{bin_ext}").unlink()

        install_clanglib = install_path / "lib/clang"
        linux_prebuilt_path = ClangToolchain.path_for_host(Host.Linux)

        # Remove unused python scripts. They are not installed for Windows.
        if self.host != Host.Windows64:
            python_bin_dir = install_path / "python3" / "bin"
            python_files_to_remove = [
                "2to3*",
                "easy_install*",
                "idle*",
                "pip*",
                "pydoc*",
                "python*-config",
            ]
            for file_pattern in python_files_to_remove:
                for pyfile in python_bin_dir.glob(file_pattern):
                    pyfile.unlink()

        if self.host != Host.Linux:
            # We don't build target binaries as part of the Darwin or Windows build.
            # These toolchains need to get these from the Linux prebuilts.
            #
            # The headers and libraries we care about are all in lib/clang for both
            # toolchains, and those two are intended to be identical between each host,
            # so we can just replace them with the one from the Linux toolchain.
            shutil.rmtree(install_clanglib)
            shutil.copytree(
                linux_prebuilt_path / "lib/clang",
                install_clanglib,
                symlinks=self.host is not Host.Windows64,
            )

        # The toolchain build creates a symlink to easy migration across versions in the
        # platform build. It's just confusing and wasted space in the NDK. Purge it.
        for path in install_clanglib.iterdir():
            if path.is_symlink():
                path.unlink()

        # The Clang prebuilts have the platform toolchain libraries in lib/clang. The
        # libraries we want are in runtimes_ndk_cxx.
        ndk_runtimes = linux_prebuilt_path / "runtimes_ndk_cxx"
        for version_dir in install_clanglib.iterdir():
            dst_lib_dir = version_dir / "lib/linux"
            shutil.rmtree(dst_lib_dir)
            shutil.copytree(ndk_runtimes, dst_lib_dir)

            # Create empty libatomic.a stub libraries to keep -latomic working.
            # This is needed for backwards compatibility and might be useful if
            # upstream LLVM splits out the __atomic_* APIs from the builtins.
            for arch in ndk.abis.ALL_ARCHITECTURES:
                # Only the arch-specific subdir is on the linker search path.
                subdir = {
                    ndk.abis.Arch("arm"): "arm",
                    ndk.abis.Arch("arm64"): "aarch64",
                    ndk.abis.Arch("riscv64"): "riscv64",
                    ndk.abis.Arch("x86"): "i386",
                    ndk.abis.Arch("x86_64"): "x86_64",
                }[arch]
                (dst_lib_dir / subdir / "libatomic.a").write_text(
                    textwrap.dedent(
                        """\
                    /* The __atomic_* APIs are now in libclang_rt.builtins-*.a. They might
                       eventually be broken out into a separate library -- see llvm.org/D47606. */
                    """
                    )
                )

        # Remove duplicate install locations of some runtime libraries. The toolchain
        # artifacts install these to a location the driver doesn't search. We relocate
        # these as necessary (either in this class or in Toolchain), so clean up the
        # excess. The Android runtimes are only packaged in the Linux toolchain.
        if self.host == Host.Linux:
            shutil.rmtree(install_path / "runtimes_ndk_cxx")
            shutil.rmtree(install_path / "android_libc++")

        # Remove CMake package files that should not be exposed.
        # For some reason the LLVM install includes CMake modules that expose
        # its internal APIs. We want to purge these so apps don't accidentally
        # depend on them. See http://b/142327416 for more info.
        shutil.rmtree(install_path / "lib/cmake")

        # Remove libc++.a and libc++abi.a on Darwin. Now that these files are
        # universal binaries, they break notarization. Maybe it is possible to
        # fix notarization by using ditto to preserve APFS extended attributes.
        # See https://developer.apple.com/forums/thread/126038.
        if self.host == Host.Darwin:
            (install_path / "lib/libc++.a").unlink()
            (install_path / "lib/libc++abi.a").unlink()

        # Strip some large binaries and libraries. This is awkward, hand-crafted
        # logic to select most of the biggest offenders, but could be
        # greatly improved, although handling Mac, Windows, and Linux
        # elegantly and consistently is a bit tricky.
        strip_cmd = ClangToolchain(Host.current()).strip
        for file in ndk.paths.walk(bin_dir, directories=False):
            if not file.is_file() or file.is_symlink():
                continue
            if Host.current().is_windows:
                if file.suffix == ".exe":
                    subprocess.check_call([str(strip_cmd), str(file)])
            elif file.stat().st_size > 100000:
                subprocess.check_call([str(strip_cmd), str(file)])
        for file in ndk.paths.walk(install_clanglib, directories=False):
            if not file.is_file() or file.is_symlink():
                continue
            if file.name == "lldb-server":
                subprocess.check_call([str(strip_cmd), str(file)])
            if (
                file.name.startswith("libLLVM.")
                or file.name.startswith("libclang.")
                or file.name.startswith("libclang-cpp.")
                or file.name.startswith("libLTO.")
                or file.name.startswith("liblldb.")
            ):
                subprocess.check_call([str(strip_cmd), "--strip-unneeded", str(file)])

        for lib in (install_path / "lib").iterdir():
            broken_symlinks = {
                "libc++abi.so.1.0",
                "libc++abi.so",
                "libc++.so.1.0",
            }

            if lib.name in broken_symlinks:
                self._check_and_remove_dangling_symlink(lib)

    def _check_and_remove_dangling_symlink(self, path: Path) -> None:
        """Removes an expected dangling symlink, or raises an error.

        The latest LLVM prebuilts have some dangling symlinks. It's a bug on the LLVM
        build side, but rather than wait for a respin we just clean up the problems
        here. This will raise an error whenever we upgrade to a new toolchain that
        doesn't have these problems, so we'll know when to remove the workaround.
        """
        if not path.is_symlink():
            raise RuntimeError(
                f"Expected {path} to be a symlink. Update or remove this workaround."
            )
        if (dest := path.readlink()).exists():
            raise RuntimeError(
                f"Expected {path} to be a dangling symlink, but {dest} exists. Update "
                "or remove this workaround."
            )

        path.unlink()


def versioned_so(host: Host, lib: str, version: str) -> str:
    """Returns the formatted versioned library for the given host.

    >>> versioned_so(Host.Darwin, 'libfoo', '0')
    'libfoo.0.dylib'
    >>> versioned_so(Host.Linux, 'libfoo', '0')
    'libfoo.so.0'
    """
    if host is Host.Darwin:
        return f"{lib}.{version}.dylib"
    if host is Host.Linux:
        return f"{lib}.so.{version}"
    raise ValueError(f"Unsupported host: {host}")


@register
class ShaderTools(ndk.builds.CMakeModule):
    name = "shader-tools"
    src = ANDROID_DIR / "external" / "shaderc" / "shaderc"
    install_path = Path("shader-tools/{host}")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {"clang"}

    @property
    def notices(self) -> Iterator[Path]:
        base = ANDROID_DIR / "external/shaderc"
        shaderc_dir = base / "shaderc"
        glslang_dir = base / "glslang"
        spirv_dir = base / "spirv-headers"
        yield shaderc_dir / "LICENSE"
        yield shaderc_dir / "third_party/LICENSE.spirv-tools"
        yield glslang_dir / "LICENSE.txt"
        yield spirv_dir / "LICENSE"

    @property
    def defines(self) -> Dict[str, str]:
        gtest_dir = ANDROID_DIR / "external" / "googletest"
        effcee_dir = ANDROID_DIR / "external" / "effcee"
        re2_dir = ANDROID_DIR / "external" / "regex-re2"
        spirv_headers_dir = self.src.parent / "spirv-headers"
        defines = {
            "SHADERC_EFFCEE_DIR": str(effcee_dir),
            "SHADERC_RE2_DIR": str(re2_dir),
            "SHADERC_GOOGLE_TEST_DIR": str(gtest_dir),
            "SHADERC_THIRD_PARTY_ROOT_DIR": str(self.src.parent),
            "EFFCEE_GOOGLETEST_DIR": str(gtest_dir),
            "EFFCEE_RE2_DIR": str(re2_dir),
            # SPIRV-Tools tests require effcee and re2.
            # Don't enable RE2 testing because it's long and not useful to us.
            "RE2_BUILD_TESTING": "OFF",
            "SPIRV-Headers_SOURCE_DIR": str(spirv_headers_dir),
        }
        return defines

    @property
    def flags(self) -> List[str]:
        return super().flags + [
            "-Wno-unused-command-line-argument",
            "-fno-rtti",
            "-fno-exceptions",
        ]

    @property
    def ldflags(self) -> List[str]:
        ldflags = super().ldflags
        if self.host == Host.Linux:
            # Our libc++.so.1 re-exports libc++abi, and it will be installed in
            # the same directory as the executables.
            ldflags += ["-Wl,-rpath,\\$ORIGIN"]
        if self.host == Host.Windows64:
            # TODO: The shaderc CMake files already pass these options for
            # gcc+mingw but not for clang+mingw. See
            # https://github.com/android/ndk/issues/1464.
            ldflags += ["-static", "-static-libgcc", "-static-libstdc++"]
        return ldflags

    @property
    def env(self) -> Dict[str, str]:
        # Sets path for libc++, for ctest.
        if self.host == Host.Linux:
            return {"LD_LIBRARY_PATH": str(self._libcxx_dir)}
        return {}

    @property
    def _libcxx_dir(self) -> Path:
        return self.get_dep("clang").get_build_host_install() / "lib"

    @property
    def _libcxx(self) -> List[Path]:
        path = self._libcxx_dir
        if self.host == Host.Linux:
            return [path / "libc++.so"]
        return []

    def build(self) -> None:
        # These have never behaved properly on Darwin. Local builds haven't worked in
        # years (presumably an XCode difference), and now CI is failing because of the
        # same libc++ mismatch as in
        # https://android-review.googlesource.com/c/platform/ndk/+/2657073. The local
        # build fails before the failure that happens in CI, so I can't test a fix for
        # the CI issue. Just disable this until someone that's familiar with the tests
        # has the time to fix them.
        self.run_ctest = self.host is not Host.Darwin
        super().build()

    def install(self) -> None:
        self.get_install_path().mkdir(parents=True, exist_ok=True)
        ext = ".exe" if self.host.is_windows else ""
        files_to_copy = [
            f"glslc{ext}",
            f"spirv-as{ext}",
            f"spirv-dis{ext}",
            f"spirv-val{ext}",
            f"spirv-cfg{ext}",
            f"spirv-opt{ext}",
            f"spirv-link{ext}",
            f"spirv-reduce{ext}",
        ]
        scripts_to_copy = ["spirv-lesspipe.sh"]

        # Copy to install tree.
        for src in files_to_copy + scripts_to_copy:
            shutil.copy2(
                self.builder.install_directory / "bin" / src, self.get_install_path()
            )

        # Symlink libc++ to install path.
        for lib in self._libcxx:
            symlink_name = self.get_install_path() / lib.name
            make_symlink(symlink_name, lib)


@register
class Make(ndk.builds.CMakeModule):
    name = "make"
    install_path = Path("prebuilt/{host}")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    src = ANDROID_DIR / "toolchain/make"
    deps = {"clang"}

    @property
    def notices(self) -> Iterator[Path]:
        yield self.src / "COPYING"


@register
class Yasm(ndk.builds.AutoconfModule):
    name = "yasm"
    install_path = Path("prebuilt/{host}")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    src = ANDROID_DIR / "toolchain/yasm"

    @property
    def notices(self) -> Iterator[Path]:
        files = [
            "Artistic.txt",
            "BSD.txt",
            "COPYING",
            "GNU_GPL-2.0",
            "GNU_LGPL-2.0",
        ]
        for name in files:
            yield self.src / name


@register
class NdkWhich(ndk.builds.FileModule):
    name = "ndk-which"
    install_path = Path("prebuilt/{host}/bin/ndk-which")
    src = NDK_DIR / "ndk-which"


def iter_python_lint_paths() -> Iterator[Path]:
    ndk_package_path = Path("ndk")
    yield ndk_package_path
    for app in iter_python_app_modules():
        if ndk_package_path not in app.package.parents:
            yield app.package


@register
class Black(ndk.builds.LintModule):
    name = "black"

    def run(self) -> None:
        if not shutil.which("black"):
            logging.warning(
                "Skipping format-checking. black was not found on your path."
            )
            return
        subprocess.check_call(["black", "--check", "."])


@register
class Isort(ndk.builds.LintModule):
    name = "isort"

    def run(self) -> None:
        if not shutil.which("isort"):
            logging.warning("Skipping isort. isort was not found on your path.")
            return
        subprocess.check_call(["isort", "--check", "."])


@register
class Pylint(ndk.builds.LintModule):
    name = "pylint"

    def run(self) -> None:
        if not shutil.which("pylint"):
            logging.warning("Skipping linting. pylint was not found on your path.")
            return
        pylint: Sequence[str | Path] = [
            "pylint",
            "--rcfile=" + str(ANDROID_DIR / "ndk/pyproject.toml"),
            "--score=n",
            "build",
            "tests",
            *iter_python_lint_paths(),
        ]
        subprocess.check_call(pylint)


@register
class Mypy(ndk.builds.LintModule):
    name = "mypy"

    def run(self) -> None:
        if not shutil.which("mypy"):
            logging.warning("Skipping type-checking. mypy was not found on your path.")
            return
        subprocess.check_call(
            [
                "mypy",
                "--config-file",
                str(ANDROID_DIR / "ndk/pyproject.toml"),
                *iter_python_lint_paths(),
            ]
        )


@register
class Pytest(ndk.builds.LintModule):
    name = "pytest"
    deps = {"ndk-stack", "ndk-stack-shortcut"}

    def run(self) -> None:
        if not shutil.which("pytest"):
            logging.warning("Skipping pytest. pytest was not found on your path.")
            return
        subprocess.check_call(["pytest", "ndk", "tests/pytest"])


@register
class PythonLint(ndk.builds.MetaModule):
    name = "pythonlint"
    deps = {"black", "isort", "mypy", "pylint", "pytest"}


@register
class Toolbox(ndk.builds.Module):
    name = "toolbox"
    install_path = Path("prebuilt/{host}/bin")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    notice = NDK_DIR / "sources/host-tools/toolbox/NOTICE"

    def build_exe(self, src: Path, name: str) -> None:
        toolchain = ClangToolchain(self.host)
        cmd = [
            str(toolchain.cc),
            "-s",
            "-o",
            str(self.intermediate_out_dir / f"{name}.exe"),
            str(src),
        ] + toolchain.flags
        subprocess.run(cmd, check=True)

    def build(self) -> None:
        if not self.host.is_windows:
            print(f"Nothing to do for {self.host}")
            return

        self.intermediate_out_dir.mkdir(parents=True, exist_ok=True)

        src_dir = NDK_DIR / "sources/host-tools/toolbox"
        self.build_exe(src_dir / "echo_win.c", "echo")
        self.build_exe(src_dir / "cmp_win.c", "cmp")

    def install(self) -> None:
        if not self.host.is_windows:
            print(f"Nothing to do for {self.host}")
            return

        install_dir = self.get_install_path()
        install_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(self.intermediate_out_dir / "echo.exe", install_dir)
        shutil.copy2(self.intermediate_out_dir / "cmp.exe", install_dir)


def install_exe(out_dir: Path, install_dir: Path, name: str, host: Host) -> None:
    ext = ".exe" if host.is_windows else ""
    exe_name = name + ext
    src = out_dir / exe_name
    dst = install_dir / exe_name

    install_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def make_linker_script(path: Path, libs: List[str]) -> None:
    path.write_text(f"INPUT({' '.join(libs)})\n")


@register
class LibShaderc(ndk.builds.Module):
    name = "libshaderc"
    install_path = Path("sources/third_party/shaderc")
    src = ANDROID_DIR / "external/shaderc"
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    @property
    def notices(self) -> Iterator[Path]:
        shaderc_dir = self.src / "shaderc"
        glslang_dir = self.src / "glslang"
        yield shaderc_dir / "LICENSE"
        yield glslang_dir / "LICENSE.txt"
        yield shaderc_dir / "third_party/LICENSE.spirv-tools"

    def build(self) -> None:
        pass

    def install(self) -> None:
        copies = [
            {
                "source_dir": str(self.src / "shaderc"),
                "dest_dir": "",
                "files": [
                    "Android.mk",
                    "libshaderc/Android.mk",
                    "libshaderc_util/Android.mk",
                    "third_party/Android.mk",
                    "utils/update_build_version.py",
                    "CHANGES",
                ],
                "dirs": [
                    "libshaderc/include",
                    "libshaderc/src",
                    "libshaderc_util/include",
                    "libshaderc_util/src",
                ],
            },
            {
                "source_dir": str(self.src / "spirv-tools"),
                "dest_dir": "third_party/spirv-tools",
                "files": [
                    "utils/generate_grammar_tables.py",
                    "utils/generate_language_headers.py",
                    "utils/generate_registry_tables.py",
                    "utils/update_build_version.py",
                    "Android.mk",
                    "CHANGES",
                ],
                "dirs": ["include", "source"],
            },
            {
                "source_dir": str(self.src / "spirv-headers"),
                "dest_dir": "third_party/spirv-tools/external/spirv-headers",
                "dirs": ["include"],
                "files": [
                    "include/spirv/1.0/spirv.py",
                    "include/spirv/1.1/spirv.py",
                    "include/spirv/1.2/spirv.py",
                    "include/spirv/uinified1/spirv.py",
                ],
            },
            {
                "source_dir": str(self.src / "glslang"),
                "dest_dir": "third_party/glslang",
                "files": [
                    "Android.mk",
                    "glslang/OSDependent/osinclude.h",
                    # Build version info is generated from the CHANGES.md file.
                    "CHANGES.md",
                    "build_info.h.tmpl",
                    "build_info.py",
                    "StandAlone/DirStackFileIncluder.h",
                    "StandAlone/ResourceLimits.h",
                ],
                "dirs": [
                    "SPIRV",
                    "OGLCompilersDLL",
                    "glslang/CInterface",
                    "glslang/GenericCodeGen",
                    "hlsl",
                    "glslang/HLSL",
                    "glslang/Include",
                    "glslang/MachineIndependent",
                    "glslang/OSDependent/Unix",
                    "glslang/Public",
                ],
            },
        ]

        default_ignore_patterns = shutil.ignore_patterns(
            "*CMakeLists.txt", "*.py", "*test.h", "*test.cc"
        )

        install_dir = self.get_install_path()
        if install_dir.exists():
            shutil.rmtree(install_dir)

        for properties in copies:
            source_dir = properties["source_dir"]
            assert isinstance(source_dir, str)
            assert isinstance(properties["dest_dir"], str)
            dest_dir = install_dir / properties["dest_dir"]
            for d in properties["dirs"]:
                assert isinstance(d, str)
                src = Path(source_dir) / d
                dst = Path(dest_dir) / d
                print(src, " -> ", dst)
                shutil.copytree(src, dst, ignore=default_ignore_patterns)
            for f in properties["files"]:
                print(source_dir, ":", dest_dir, ":", f)
                # Only copy if the source file exists.  That way
                # we can update this script in anticipation of
                # source files yet-to-come.
                assert isinstance(f, str)
                if (Path(source_dir) / f).exists():
                    install_file(f, Path(source_dir), Path(dest_dir))
                else:
                    print(source_dir, ":", dest_dir, ":", f, "SKIPPED")


@register
class CpuFeatures(ndk.builds.PackageModule):
    name = "cpufeatures"
    install_path = Path("sources/android/cpufeatures")
    src = NDK_DIR / "sources/android/cpufeatures"


@register
class NativeAppGlue(ndk.builds.PackageModule):
    name = "native_app_glue"
    install_path = Path("sources/android/native_app_glue")
    src = NDK_DIR / "sources/android/native_app_glue"


@register
class NdkHelper(ndk.builds.PackageModule):
    name = "ndk_helper"
    install_path = Path("sources/android/ndk_helper")
    src = NDK_DIR / "sources/android/ndk_helper"


@register
class Gtest(ndk.builds.PackageModule):
    name = "gtest"
    install_path = Path("sources/third_party/googletest")
    src = ANDROID_DIR / "external/googletest/googletest"

    def install(self) -> None:
        super().install()
        # Docs are moved to top level directory.
        shutil.rmtree(self.get_install_path() / "docs")


@register
class Sysroot(ndk.builds.Module):
    name = "sysroot"
    install_path = Path("sysroot")
    notice = PREBUILT_SYSROOT / "NOTICE"
    intermediate_module = True
    deps = {"clang"}

    def __init__(self) -> None:
        super().__init__()
        self.crt_builder: CrtObjectBuilder | None = None

    def build(self) -> None:
        build_dir = self.out_dir / self.install_path
        if build_dir.exists():
            shutil.rmtree(build_dir)

        assert self.context is not None
        self.crt_builder = CrtObjectBuilder(
            self.get_dep("clang").get_build_host_install(),
            build_dir,
            self.context.build_number,
        )
        self.crt_builder.build()

    def install(self) -> None:
        install_path = self.get_install_path()
        if install_path.exists():
            shutil.rmtree(install_path)
        shutil.copytree(PREBUILT_SYSROOT, install_path)
        if self.host is not Host.Linux:
            # linux/netfilter has some headers with names that differ only
            # by case, which can't be extracted to a case-insensitive
            # filesystem, which are the defaults for Darwin and Windows :(
            #
            # There isn't really a good way to decide which of these to
            # keep and which to remove. The capitalized versions expose
            # different APIs, but we can't keep both. So far no one has
            # filed bugs about needing either API, so let's just dedup them
            # consistently and we can change that if we hear otherwise.
            remove_paths = [
                "usr/include/linux/netfilter_ipv4/ipt_ECN.h",
                "usr/include/linux/netfilter_ipv4/ipt_TTL.h",
                "usr/include/linux/netfilter_ipv6/ip6t_HL.h",
                "usr/include/linux/netfilter/xt_CONNMARK.h",
                "usr/include/linux/netfilter/xt_DSCP.h",
                "usr/include/linux/netfilter/xt_MARK.h",
                "usr/include/linux/netfilter/xt_RATEEST.h",
                "usr/include/linux/netfilter/xt_TCPMSS.h",
            ]
            for remove_path in remove_paths:
                os.remove(install_path / remove_path)

        assert self.context is not None
        NdkVersionHeaderGenerator(
            ndk.config.major,
            ndk.config.hotfix,
            ndk.config.beta,
            self.context.build_number,
            ndk.config.canary,
        ).write(install_path / "usr/include/android/ndk-version.h")

        # Install the CRT objects that we just built.
        assert self.crt_builder is not None
        for abi, api, path in self.crt_builder.artifacts:
            lib_dir_dst = (
                install_path / "usr/lib" / ndk.abis.abi_to_triple(abi) / str(api)
            )
            obj_dst = lib_dir_dst / path.name
            shutil.copy2(path, obj_dst)


def write_clang_shell_script(
    wrapper_path: Path, clang_name: str, flags: List[str]
) -> None:
    wrapper_path.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            bin_dir=`dirname "$0"`
            if [ "$1" != "-cc1" ]; then
                "$bin_dir/{clang_name}" {' '.join(flags)} "$@"
            else
                # Target is already an argument.
                "$bin_dir/{clang_name}" "$@"
            fi
            """
        )
    )

    mode = os.stat(wrapper_path).st_mode
    os.chmod(wrapper_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_clang_batch_script(
    wrapper_path: Path, clang_name: str, flags: List[str]
) -> None:
    wrapper_path.write_text(
        textwrap.dedent(
            f"""\
            @echo off
            setlocal
            call :find_bin
            if "%~1" == "-cc1" goto :L

            set "_BIN_DIR=" && "%_BIN_DIR%{clang_name}" {' '.join(flags)} %*
            if ERRORLEVEL 1 exit /b 1
            goto :done

            :L
            rem Target is already an argument.
            set "_BIN_DIR=" && "%_BIN_DIR%{clang_name}" %*
            if ERRORLEVEL 1 exit /b 1
            goto :done

            :find_bin
            rem Accommodate a quoted arg0, e.g.: "clang"
            rem https://github.com/android-ndk/ndk/issues/616
            set _BIN_DIR=%~dp0
            exit /b

            :done
            """
        )
    )


def write_clang_wrapper(
    install_dir: Path, api: int, triple: str, is_windows: bool
) -> None:
    """Writes a target-specific Clang wrapper.

    This wrapper can be used to target the given architecture/API combination
    without needing to specify -target. These obviate the need for standalone
    toolchains.

    Ideally these would be symlinks rather than wrapper scripts to avoid the
    unnecessary indirection (Clang will infer its default target based on
    argv[0]), but the SDK manager can't install symlinks and Windows only
    allows administrators to create them.
    """
    exe_suffix = ".exe" if is_windows else ""

    if triple.startswith("arm-linux"):
        triple = "armv7a-linux-androideabi"

    wrapper_path = install_dir / "{}{}-clang".format(triple, api)
    wrapperxx_path = wrapper_path.parent / (wrapper_path.name + "++")

    flags = ["--target={}{}".format(triple, api)]

    # TODO: Hoist into the driver.
    if triple.startswith("i686") and api < 24:
        flags.append("-mstackrealign")

    # Write shell scripts even for Windows to support WSL and Cygwin.
    write_clang_shell_script(wrapper_path, "clang" + exe_suffix, flags)
    write_clang_shell_script(wrapperxx_path, "clang++" + exe_suffix, flags)
    if is_windows:
        write_clang_batch_script(
            wrapper_path.with_suffix(".cmd"), "clang" + exe_suffix, flags
        )
        write_clang_batch_script(
            wrapperxx_path.with_suffix(".cmd"), "clang++" + exe_suffix, flags
        )


@register
class Toolchain(ndk.builds.Module):
    """The LLVM toolchain.

    The toolchain includes Clang, LLD, libc++, and LLVM's binutils.
    """

    name = "toolchain"
    # This is installed to the Clang location to avoid migration pain.
    install_path = Path("toolchains/llvm/prebuilt/{host}")
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {
        "clang",
        "make",
        "sysroot",
        "system-stl",
        "yasm",
    }

    @property
    def notices(self) -> Iterator[Path]:
        yield from Clang().notices
        yield from Yasm().notices
        yield from Sysroot().notices
        yield from SystemStl().notices

    @property
    def sysroot_install_path(self) -> Path:
        return self.get_install_path() / "sysroot"

    def toolchain_libcxx_path_for(self, abi: Abi) -> Path:
        """Returns the path to the toolchain's NDK libc++ artifacts.

        The toolchain artifacts install all the libc++ artifacts to the android_libc++
        subdirectory rather than anywhere that the driver can find them (because that's
        still WIP). These are only included in the Linux artifacts.
        """
        # The libc++ directories in the toolchain artifacts use yet another spelling of
        # each ABI.
        libcxx_arch_name = {
            Abi("armeabi-v7a"): "arm",
            Abi("arm64-v8a"): "aarch64",
            Abi("riscv64"): "riscv64",
            Abi("x86"): "i386",
            Abi("x86_64"): "x86_64",
        }[abi]
        return (
            ClangToolchain.path_for_host(Host.Linux)
            / "android_libc++/ndk"
            / libcxx_arch_name
        )

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_dir = self.get_install_path()
        yasm_dir = self.get_dep("yasm").get_install_path()
        sysroot_dir = self.get_dep("sysroot").get_install_path()
        system_stl_dir = self.get_dep("system-stl").get_install_path()

        shutil.copytree(sysroot_dir, self.sysroot_install_path, dirs_exist_ok=True)

        exe = ".exe" if self.host.is_windows else ""
        shutil.copy2(
            yasm_dir / "bin" / ("yasm" + exe),
            install_dir / "bin",
        )

        bin_dir = Path(install_dir) / "bin"
        lld = bin_dir / f"ld.lld{exe}"
        new_bin_ld = bin_dir / f"ld{exe}"

        if self.host.is_windows:
            shutil.copyfile(lld, new_bin_ld)
            shutil.copystat(lld, new_bin_ld)
        else:
            # This reduces the size of the NDK by 60M on non-Windows.
            os.symlink(lld.name, new_bin_ld)

        for api in ALL_API_LEVELS:
            for abi in ndk.abis.iter_abis_for_api(api):
                triple = ndk.abis.abi_to_triple(abi)
                write_clang_wrapper(
                    install_dir / "bin", api, triple, self.host.is_windows
                )

        # Clang searches for libstdc++ headers at $GCC_PATH/../include/c++. It
        # maybe be worth adding a search for the same path within the usual
        # sysroot location to centralize these, or possibly just remove them
        # from the NDK since they aren't particularly useful anyway.
        system_stl_hdr_dir = install_dir / "include/c++"
        system_stl_hdr_dir.mkdir(parents=True)
        system_stl_inc_src = system_stl_dir / "include"
        system_stl_inc_dst = system_stl_hdr_dir / "4.9.x"
        shutil.copytree(system_stl_inc_src, system_stl_inc_dst)
        self.relocate_libcxx()
        self.create_libcxx_linker_scripts()

    def relocate_libcxx(self) -> None:
        """Relocate libc++ so its discoverable by the Clang driver.

        The NDK libc++ in the toolchain prebuilts is not installed to a location that
        the driver is able to find by default. Move it to a driver searched directory.
        """
        # The Clang driver automatically uses the following library search directories
        # (relative to the LLVM install root, for an aarch64-linux-android21 target and
        # LLVM 17):
        #
        # 1. lib/clang/17/lib/linux/aarch64
        # 2. bin/../sysroot/usr/lib/aarch64-linux-android/21
        # 3. bin/../sysroot/usr/lib/aarch64-linux-android
        # 4. bin/../sysroot/usr/lib
        #
        # The sysroot directory comes from the platform's sysroot artifact, so it's best
        # to avoid installing to that (if we install there, the platform's artifact
        # can't be used directly; it needs to have NDK components installed to it).
        #
        # However, AGP (and probably other systems) expect to find libc++_shared.so in
        # sysroot/usr/lib/$TRIPLE, so we should continue using that path for the time
        # being. At some point we should move all the libc++ details into the
        # toolchain's directories so it's easier to use an arbitrary sysroot (e.g. for
        # previewing Android APIs without needing a whole new NDK), but we can't do that
        # for the headers yet anyway (see below). Keep compatible for now.
        usr_lib = self.sysroot_install_path / "usr/lib"
        for abi in ALL_ABIS:
            dest = usr_lib / ndk.abis.abi_to_triple(abi)
            src = self.toolchain_libcxx_path_for(abi) / "lib"
            for lib in src.iterdir():
                shutil.copy2(lib, dest / lib.name)

        # libc++ headers for Android will currently only be found in the sysroot:
        # https://github.com/llvm/llvm-project/blob/c64f10bfe20308ebc7d5d18912cd0ba82a44eaa1/clang/lib/Driver/ToolChains/Gnu.cpp#L3080-L3084
        #
        # We ought to revert that driver behavior (which shouldn't be contentious, since
        # it's our patch in the first place), but for now we'll continue installing the
        # libc++ headers to the sysroot.
        src = ClangToolchain.path_for_host(Host.Linux) / "include/c++/v1"
        dest = self.sysroot_install_path / "usr/include/c++/v1"
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)

        # There's also an Android-specific __config_site header that we need to install.
        shutil.copy2(self.find_libcxx_config_site(), dest / "__config_site")

    def find_libcxx_config_site(self) -> Path:
        """Finds the __config_site file for the NDK libc++.

        That header exists per-ABI in the android_libc++ directory, but they should all
        be identical and the driver doesn't search per-ABI include directories for
        libc++. Verify that they are actually identical and return one of them
        arbitrarily.
        """
        config_sites: list[Path] = []
        for abi in ALL_ABIS:
            includes = self.toolchain_libcxx_path_for(abi) / "include"
            config_sites.extend(includes.glob("**/__config_site"))
        first = config_sites[0]
        contents = first.read_bytes()
        for config_site in config_sites[1:]:
            if config_site.read_bytes() != contents:
                raise RuntimeError(
                    f"Expected all NDK __config_site files to be identical. {first} "
                    f"and {config_site} have different contents."
                )
        return first

    def create_libcxx_linker_scripts(self) -> None:
        """Install per-target linker scripts for libc++.so and libc++.a.

        Clang is going to try to use `-lc++`, not `-lc++_shared` or
        `-lc++_static -lc++abi`. Linker scripts paper over those details.

        These are per-target for historical reasons (pre-21 needed libandroid_support,
        arm32 needed libunwind). These could probably be reduced to a single linker
        script now.
        """
        install_dir = self.get_install_path()
        for api in ALL_API_LEVELS:
            for abi in ndk.abis.iter_abis_for_api(api):
                triple = ndk.abis.abi_to_triple(abi)
                dst_dir = install_dir / "sysroot/usr/lib" / triple / str(api)

                (dst_dir / "libc++.so").write_text("INPUT(-lc++_shared)")
                (dst_dir / "libc++.a").write_text("INPUT(-lc++_static -lc++abi)")


def make_format_value(value: Any) -> Any:
    if isinstance(value, list):
        return " ".join(value)
    return value


def var_dict_to_make(var_dict: Dict[str, Any]) -> str:
    lines = []
    for name, value in var_dict.items():
        lines.append("{} := {}".format(name, make_format_value(value)))
    return os.linesep.join(lines)


def cmake_format_value(value: Any) -> Any:
    if isinstance(value, list):
        return ";".join(value)
    return value


def var_dict_to_cmake(var_dict: Dict[str, Any]) -> str:
    lines = []
    for name, value in var_dict.items():
        lines.append('set({} "{}")'.format(name, cmake_format_value(value)))
    return os.linesep.join(lines)


def abis_meta_transform(metadata: dict[str, Any]) -> dict[str, Any]:
    default_abis = []
    deprecated_abis = []
    lp32_abis = []
    lp64_abis = []
    abi_infos = {}
    for abi, abi_data in metadata.items():
        bitness = abi_data["bitness"]
        if bitness == 32:
            lp32_abis.append(abi)
        elif bitness == 64:
            lp64_abis.append(abi)
        else:
            raise ValueError("{} bitness is unsupported value: {}".format(abi, bitness))

        if abi_data["default"]:
            default_abis.append(abi)

        if abi_data["deprecated"]:
            deprecated_abis.append(abi)

        proc = abi_data["proc"]
        arch = abi_data["arch"]
        triple = abi_data["triple"]
        llvm_triple = abi_data["llvm_triple"]
        abi_infos[f"NDK_ABI_{abi}_PROC"] = proc
        abi_infos[f"NDK_ABI_{abi}_ARCH"] = arch
        abi_infos[f"NDK_ABI_{abi}_TRIPLE"] = triple
        abi_infos[f"NDK_ABI_{abi}_LLVM_TRIPLE"] = llvm_triple
        abi_infos[f"NDK_ABI_{abi}_MIN_OS_VERSION"] = int(abi_data["min_os_version"])

    meta_vars = {
        "NDK_DEFAULT_ABIS": sorted(default_abis),
        "NDK_DEPRECATED_ABIS": sorted(deprecated_abis),
        "NDK_KNOWN_DEVICE_ABI32S": sorted(lp32_abis),
        "NDK_KNOWN_DEVICE_ABI64S": sorted(lp64_abis),
        "NDK_KNOWN_DEVICE_ABIS": sorted(lp32_abis + lp64_abis),
    }
    meta_vars.update(abi_infos)

    return meta_vars


def platforms_meta_transform(metadata: dict[str, Any]) -> dict[str, Any]:
    meta_vars = {
        "NDK_MIN_PLATFORM_LEVEL": metadata["min"],
        "NDK_MAX_PLATFORM_LEVEL": metadata["max"],
    }

    for src, dst in metadata["aliases"].items():
        name = "NDK_PLATFORM_ALIAS_{}".format(src)
        value = "android-{}".format(dst)
        meta_vars[name] = value
    return meta_vars


def system_libs_meta_transform(metadata: dict[str, Any]) -> dict[str, Any]:
    # This file also contains information about the first supported API level
    # for each library. We could use this to provide better diagnostics in
    # ndk-build, but currently do not.
    return {"NDK_SYSTEM_LIBS": sorted(metadata.keys())}


@register
class NdkBuild(ndk.builds.PackageModule):
    name = "ndk-build"
    install_path = Path("build")
    src = NDK_DIR / "build"
    notice = NDK_DIR / "NOTICE"

    deps = {
        "meta",
        "clang",
    }

    def install(self) -> None:
        super().install()

        self.install_ndk_version_makefile()
        self.generate_cmake_compiler_id()

        self.generate_language_specific_metadata("abis", abis_meta_transform)

        self.generate_language_specific_metadata("platforms", platforms_meta_transform)

        self.generate_language_specific_metadata(
            "system_libs", system_libs_meta_transform
        )

    def install_ndk_version_makefile(self) -> None:
        """Generates a version.mk for ndk-build."""
        version_mk = Path(self.get_install_path()) / "core/version.mk"
        version_mk.write_text(
            textwrap.dedent(
                f"""\
            NDK_MAJOR := {ndk.config.major}
            NDK_MINOR := {ndk.config.hotfix}
            NDK_BETA := {ndk.config.beta}
            NDK_CANARY := {str(ndk.config.canary).lower()}
            """
            )
        )

    @staticmethod
    def get_clang_version(clang: Path) -> str:
        """Invokes Clang to determine its version string."""
        result = subprocess.run(
            [str(clang), "--version"], capture_output=True, encoding="utf-8", check=True
        )
        version_line = result.stdout.splitlines()[0]
        # Format of the version line is:
        # Android ($BUILD, based on $REV) clang version x.y.z ($GIT_URL $SHA)
        match = re.search(r"clang version ([0-9.]+)\s", version_line)
        if match is None:
            raise RuntimeError(f"Could not find Clang version in:\n{result.stdout}")
        return match.group(1)

    def generate_cmake_compiler_id(self) -> None:
        """Generates compiler ID information for old versions of CMake."""
        compiler_id_file = Path(self.get_install_path()) / "cmake/compiler_id.cmake"
        clang_prebuilts = Path(self.get_dep("clang").get_build_host_install())
        clang = clang_prebuilts / "bin/clang"
        clang_version = self.get_clang_version(clang)

        compiler_id_file.write_text(
            textwrap.dedent(
                f"""\
            # The file is automatically generated when the NDK is built.
            set(CMAKE_ASM_COMPILER_VERSION {clang_version})
            set(CMAKE_C_COMPILER_VERSION {clang_version})
            set(CMAKE_CXX_COMPILER_VERSION {clang_version})
            """
            )
        )

    def generate_language_specific_metadata(
        self, name: str, func: Callable[[dict[str, Any]], dict[str, Any]]
    ) -> None:
        install_path = self.get_install_path()
        json_path = self.get_dep("meta").get_install_path() / (name + ".json")
        with json_path.open(encoding="utf-8") as json_file:
            meta = json.load(json_file)
        meta_vars = func(meta)

        (install_path / f"core/{name}.mk").write_text(var_dict_to_make(meta_vars))
        (install_path / f"cmake/{name}.cmake").write_text(var_dict_to_cmake(meta_vars))


@register
class PythonPackages(ndk.builds.PackageModule):
    name = "python-packages"
    install_path = Path("python-packages")
    src = ANDROID_DIR / "development/python-packages"


@register
class SystemStl(ndk.builds.PackageModule):
    name = "system-stl"
    install_path = Path("sources/cxx-stl/system")
    src = NDK_DIR / "sources/cxx-stl/system"


@register
class SimplePerf(ndk.builds.Module):
    name = "simpleperf"
    install_path = Path("simpleperf")
    notice = ANDROID_DIR / "prebuilts/simpleperf/NOTICE"

    def build(self) -> None:
        pass

    def install(self) -> None:
        print("Installing simpleperf...")
        install_dir = self.get_install_path()
        if install_dir.exists():
            shutil.rmtree(install_dir)
        install_dir.mkdir(parents=True)

        simpleperf_path = ndk.paths.android_path("prebuilts/simpleperf")
        dirs = [
            Path("app_api"),
            Path("bin/android"),
            Path("doc"),
            Path("inferno"),
            Path("proto"),
            Path("purgatorio"),
        ]
        host_bin_dir = "windows" if self.host.is_windows else self.host.value
        dirs.append(Path("bin") / host_bin_dir)
        for d in dirs:
            shutil.copytree(simpleperf_path / d, install_dir / d)

        for item in os.listdir(simpleperf_path):
            should_copy = False
            if item.endswith(".py") and item != "update.py":
                should_copy = True
            elif item == "report_html.js":
                should_copy = True
            elif item == "inferno.sh" and not self.host.is_windows:
                should_copy = True
            elif item == "inferno.bat" and self.host.is_windows:
                should_copy = True
            if should_copy:
                shutil.copy2(simpleperf_path / item, install_dir)

        shutil.copy2(simpleperf_path / "ChangeLog", install_dir)


@register
class Changelog(ndk.builds.FileModule):
    name = "changelog"
    install_path = Path("CHANGELOG.md")
    src = NDK_DIR / f"docs/changelogs/Changelog-r{ndk.config.major}.md"
    no_notice = True


@register
class NdkGdb(ndk.builds.PythonApplication):
    name = "ndk-gdb"
    install_path = Path("prebuilt/{host}/bin/ndkgdb.pyz")
    notice = NDK_DIR / "NOTICE"
    package = NDK_DIR / "ndkgdb.py"
    main = "ndkgdb:main"
    pip_dependencies = [
        ANDROID_DIR / "development/python-packages/adb",
        ANDROID_DIR / "development/python-packages/gdbrunner",
    ]
    deps = {"ndk-gdb-shortcut", "ndk-lldb-shortcut"}


@register
class NdkGdbShortcut(ndk.builds.ScriptShortcutModule):
    name = "ndk-gdb-shortcut"
    install_path = Path("ndk-gdb")
    script = Path("prebuilt/{host}/bin/ndk-gdb")
    windows_ext = ".cmd"


@register
class NdkLldbShortcut(ndk.builds.ScriptShortcutModule):
    name = "ndk-lldb-shortcut"
    install_path = Path("ndk-lldb")
    script = Path("prebuilt/{host}/bin/ndk-gdb")
    windows_ext = ".cmd"


@register
class NdkStack(ndk.builds.PythonApplication):
    name = "ndk-stack"
    install_path = Path("prebuilt/{host}/bin/ndkstack.pyz")
    notice = NDK_DIR / "NOTICE"
    package = NDK_DIR / "ndkstack.py"
    main = "ndkstack:main"
    deps = {
        # PythonApplication depends on build/tools/ndk_bin_common.sh.
        "ndk-build",
        "ndk-stack-shortcut",
        # PythonApplication depends on Python, which is bundled with Clang.
        "toolchain",
    }


@register
class NdkStackShortcut(ndk.builds.ScriptShortcutModule):
    name = "ndk-stack-shortcut"
    install_path = Path("ndk-stack")
    script = Path("prebuilt/{host}/bin/ndk-stack")
    windows_ext = ".cmd"


@register
class NdkWhichShortcut(ndk.builds.ScriptShortcutModule):
    name = "ndk-which-shortcut"
    install_path = Path("ndk-which")
    script = Path("prebuilt/{host}/bin/ndk-which")
    windows_ext = ""  # There isn't really a Windows ndk-which.


@register
class NdkBuildShortcut(ndk.builds.ScriptShortcutModule):
    name = "ndk-build-shortcut"
    install_path = Path("ndk-build")
    script = Path("build/ndk-build")
    windows_ext = ".cmd"
    disallow_windows_install_path_with_spaces = True


@register
class Readme(ndk.builds.FileModule):
    name = "readme"
    install_path = Path("README.md")
    src = NDK_DIR / "UserReadme.md"


CANARY_TEXT = textwrap.dedent(
    """\
    This is a canary build of the Android NDK. It's updated almost every day.

    Canary builds are designed for early adopters and can be prone to breakage.
    Sometimes they can break completely. To aid development and testing, this
    distribution can be installed side-by-side with your existing, stable NDK
    release.
    """
)


@register
class CanaryReadme(ndk.builds.Module):
    name = "canary-readme"
    install_path = Path("README.canary")
    no_notice = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        if ndk.config.canary:
            self.get_install_path().write_text(CANARY_TEXT)


@register
class Meta(ndk.builds.PackageModule):
    name = "meta"
    install_path = Path("meta")
    src = NDK_DIR / "meta"
    no_notice = True

    deps = {
        "toolchain",
    }

    @staticmethod
    def find_max_api_level_in_prebuilts() -> int:
        max_api = 0
        for path in PREBUILT_SYSROOT.glob("usr/lib/*/*"):
            if not path.is_dir():
                continue

            try:
                api = int(path.name)
                max_api = max(max_api, api)
            except ValueError as ex:
                # Codenamed release like android-O, android-O-MR1, etc.
                # Codenamed APIs are not supported, since having
                # non-integer API directories breaks all kinds of tools, we
                # rename them when we check them in.
                raise ValueError(
                    f"Codenamed APIs are not allowed: {path}\n"
                    "Use the update_platform.py tool from the "
                    "platform/prebuilts/ndk dev branch to remove or rename it."
                ) from ex

        return max_api

    def validate(self) -> None:
        super().validate()

        max_sysroot_api = self.find_max_api_level_in_prebuilts()
        if max_sysroot_api != MAX_API_LEVEL:
            raise RuntimeError(
                f"API {max_sysroot_api} is the newest API level in {PREBUILT_SYSROOT} "
                f"sysroot but does not match meta/platforms.json max of {MAX_API_LEVEL}"
            )
        if max_sysroot_api not in API_LEVEL_ALIASES.values():
            raise RuntimeError(
                f"API {max_sysroot_api} is the newest API level in {PREBUILT_SYSROOT} "
                "but has no alias in meta/platforms.json."
            )

    def install(self) -> None:
        super().install()
        self.create_system_libs_meta()
        self.add_min_api_data_to_abis()

    def create_system_libs_meta(self) -> None:
        # Build system_libs.json based on what we find in the toolchain. We
        # only need to scan a single 32-bit architecture since these libraries
        # do not vary in availability across architectures.
        sysroot_base = (
            self.get_dep("toolchain").get_install_path()
            / "sysroot/usr/lib/arm-linux-androideabi"
        )

        system_libs: Dict[str, str] = {}
        for api_name in sorted(os.listdir(sysroot_base)):
            path = sysroot_base / api_name

            # There are also non-versioned libraries in this directory.
            if not path.is_dir():
                continue

            for lib in os.listdir(path):
                # Don't include CRT objects in the list.
                if not lib.endswith(".so"):
                    continue

                if not lib.startswith("lib"):
                    raise RuntimeError(
                        "Found unexpected file in sysroot: {}".format(lib)
                    )

                # libc++.so is a linker script, not a system library.
                if lib == "libc++.so":
                    continue

                # We're processing each version directory in sorted order, so
                # if we've already seen this library before it is an earlier
                # version of the library.
                if lib in system_libs:
                    continue

                system_libs[lib] = api_name

        system_libs = collections.OrderedDict(sorted(system_libs.items()))

        json_path = self.get_install_path() / "system_libs.json"
        with json_path.open("w", encoding="utf-8") as json_file:
            json.dump(system_libs, json_file, indent=2, separators=(",", ": "))

    def add_min_api_data_to_abis(self) -> None:
        json_path = self.get_install_path() / "abis.json"
        with json_path.open(encoding="utf-8") as json_file:
            data = json.load(json_file)

        for abi_name, abi_data in data.items():
            abi_data["min_os_version"] = ndk.abis.min_api_for_abi(Abi(abi_name))

        with json_path.open("w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=2, separators=(",", ": "))


@register
class WrapSh(ndk.builds.PackageModule):
    name = "wrap.sh"
    install_path = Path("wrap.sh")
    src = NDK_DIR / "wrap.sh"
    no_notice = True


@register
class SourceProperties(ndk.builds.Module):
    name = "source.properties"
    install_path = Path("source.properties")
    no_notice = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        path = self.get_install_path()
        assert self.context is not None
        version = get_version_string(self.context.build_number)
        if ndk.config.beta > 0:
            version += "-beta{}".format(ndk.config.beta)

        # This file is read by the release tooling to populate the SDK manifest. Some of
        # these properties (Pkg.Desc and Pkg.Revision) will populate fields that the SDK
        # manager UI in Android Studio will use as the display name and categorization,
        # so the formats of those should not change.
        #
        # The rest is up to us. We can add new fields that can be used in the release
        # configs. Pkg.ReleaseName, for example, is used to populate that portion of the
        # name of the zip file produced by the release.
        path.write_text(
            textwrap.dedent(
                f"""\
                Pkg.Desc = Android NDK
                Pkg.Revision = {version}
                Pkg.ReleaseName = {ndk.config.release}
                """
            )
        )


def create_notice_file(path: Path, for_group: ndk.builds.NoticeGroup) -> None:
    # Using sets here so we can perform some amount of duplicate reduction. In
    # a lot of cases there will be minor differences that cause lots of
    # "duplicates", but might as well catch what we can.
    notice_files = set()
    for module in ALL_MODULES:
        if module.notice_group == for_group:
            for notice in module.notices:
                notice_files.add(notice)

    licenses = set()
    for notice_path in notice_files:
        with open(notice_path, encoding="utf-8") as notice_file:
            licenses.add(notice_file.read())

    with path.open("w", encoding="utf-8") as output_file:
        # Sorting the contents here to try to make things deterministic.
        output_file.write(os.linesep.join(sorted(list(licenses))))


def launch_build(
    worker: ndk.workqueue.Worker,
    module: ndk.builds.Module,
    log_dir: Path,
    debuggable: bool,
) -> Tuple[bool, ndk.builds.Module]:
    result = do_build(worker, module, log_dir, debuggable)
    if not result:
        return result, module
    do_install(worker, module)
    return True, module


@contextlib.contextmanager
def file_logged_context(path: Path) -> Iterator[None]:
    with path.open("w") as log_file:
        os.dup2(log_file.fileno(), sys.stdout.fileno())
        os.dup2(log_file.fileno(), sys.stderr.fileno())
        yield


def do_build(
    worker: ndk.workqueue.Worker,
    module: ndk.builds.Module,
    log_dir: Path,
    debuggable: bool,
) -> bool:
    if debuggable:
        cm: ContextManager[None] = contextlib.nullcontext()
    else:
        cm = file_logged_context(module.log_path(log_dir))
    with cm:
        try:
            worker.status = f"Building {module}..."
            module.build()
            return True
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            return False


def do_install(worker: ndk.workqueue.Worker, module: ndk.builds.Module) -> None:
    worker.status = "Installing {}...".format(module)
    module.install()


def _get_transitive_module_deps(
    module: ndk.builds.Module,
    deps: Set[ndk.builds.Module],
    unknown_deps: Set[str],
    seen: Set[ndk.builds.Module],
) -> None:
    seen.add(module)

    for name in module.deps:
        if name not in NAMES_TO_MODULES:
            unknown_deps.add(name)
            continue

        dep = NAMES_TO_MODULES[name]
        if dep in seen:
            # Cycle detection is already handled by ndk.deps.DependencyManager.
            # Just avoid falling into an infinite loop here and let that do the
            # work.
            continue

        deps.add(dep)
        _get_transitive_module_deps(dep, deps, unknown_deps, seen)


def get_transitive_module_deps(
    module: ndk.builds.Module,
) -> Tuple[Set[ndk.builds.Module], Set[str]]:
    seen: Set[ndk.builds.Module] = set()
    deps: Set[ndk.builds.Module] = set()
    unknown_deps: Set[str] = set()
    _get_transitive_module_deps(module, deps, unknown_deps, seen)
    return deps, unknown_deps


def get_modules_to_build(
    module_names: Iterable[str],
) -> Tuple[List[ndk.builds.Module], Set[ndk.builds.Module]]:
    """Returns a list of modules to be built given a list of module names.

    The module names are those given explicitly by the user or the full list.
    In the event that the user has passed a subset of modules, we need to also
    return the dependencies of that module.
    """
    unknown_modules = set()
    modules = set()
    deps_only = set()
    for name in module_names:
        if name not in NAMES_TO_MODULES:
            # Build a list of all the unknown modules rather than error out
            # immediately so we can provide a complete error message.
            unknown_modules.add(name)

        module = NAMES_TO_MODULES[name]
        modules.add(module)

        deps, unknown_deps = get_transitive_module_deps(module)
        modules.update(deps)

        # --skip-deps may be passed if the user wants to avoid rebuilding a
        # costly dependency. It's up to the user to guarantee that the
        # dependency has actually been built. Modules are skipped by
        # immediately completing them rather than sending them to the
        # workqueue. As such, we need to return a list of which modules are
        # *only* in the list because they are dependencies rather than being a
        # part of the requested set.
        for dep in deps:
            if dep.name not in module_names:
                deps_only.add(dep)
        unknown_modules.update(unknown_deps)

    if unknown_modules:
        sys.exit("Unknown modules: {}".format(", ".join(sorted(list(unknown_modules)))))

    build_modules = []
    for module in modules:
        build_modules.append(module)

    return sorted(list(build_modules), key=str), deps_only


ALL_MODULES = [t() for t in ALL_MODULE_TYPES]
NAMES_TO_MODULES = {m.name: m for m in ALL_MODULES}


def iter_python_app_modules() -> Iterator[ndk.builds.PythonApplication]:
    """Returns an Iterator over all python applications."""
    for module in ALL_MODULES:
        if isinstance(module, ndk.builds.PythonApplication):
            yield module


def get_all_module_names() -> List[str]:
    return [m.name for m in ALL_MODULES if m.enabled]


def build_number_arg(value: str) -> int:
    if value.startswith("P"):
        # Treehugger build. Treat as a local development build.
        return 0
    return int(value)


def parse_args() -> Tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(description=inspect.getdoc(sys.modules[__name__]))

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        dest="verbosity",
        default=0,
        help="Increase logging verbosity.",
    )

    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=multiprocessing.cpu_count(),
        help=(
            "Number of parallel builds to run. Note that this will not "
            "affect the -j used for make; this just parallelizes "
            "checkbuild.py. Defaults to the number of CPUs available. "
            "Disabled when --debugabble is used."
        ),
    )

    parser.add_argument(
        "--debuggable",
        action="store_true",
        help=(
            "Prints build output to the console and disables threading to "
            "allow debugging with breakpoint()"
        ),
    )

    parser.add_argument(
        "--skip-deps",
        action="store_true",
        help=(
            "Assume that dependencies have been built and only build "
            "explicitly named modules."
        ),
    )

    package_group = parser.add_mutually_exclusive_group()
    package_group.add_argument(
        "--package",
        action="store_true",
        dest="package",
        help="Package the NDK when done building.",
    )
    package_group.add_argument(
        "--no-package",
        action="store_false",
        dest="package",
        help="Do not package the NDK when done building (default).",
    )

    test_group = parser.add_mutually_exclusive_group()
    test_group.add_argument(
        "--build-tests",
        action="store_true",
        dest="build_tests",
        default=True,
        help="Build tests when finished. Not supported when targeting Windows.",
    )
    test_group.add_argument(
        "--no-build-tests",
        action="store_false",
        dest="build_tests",
        help="Skip building tests after building the NDK.",
    )

    package_test_group = parser.add_mutually_exclusive_group()
    package_test_group.add_argument(
        "--package-tests",
        action="store_true",
        dest="package_tests",
        default=None,
        help="Package tests as build artifacts. Requires --build-tests.",
    )
    package_test_group.add_argument(
        "--no-package-tests",
        action="store_false",
        dest="package_tests",
        default=None,
        help="Don't package tests after building them.",
    )

    parser.add_argument(
        "--build-number",
        default="0",
        type=build_number_arg,
        help="Build number for use in version files.",
    )
    parser.add_argument("--release", help="Ignored. Temporarily compatibility.")

    parser.add_argument(
        "--system",
        choices=Host,
        type=Host,
        default=Host.current(),
        help="Build for the given OS.",
    )

    module_group = parser.add_mutually_exclusive_group()

    module_group.add_argument(
        "--module",
        dest="modules",
        action="append",
        default=[],
        choices=get_all_module_names(),
        help="NDK modules to build.",
    )

    return parser.parse_known_args()


def log_build_failure(log_path: Path, dist_dir: Path) -> None:
    contents = log_path.read_text()
    print(contents)

    # The build server has a build_error.log file that is supposed to be
    # the short log of the failure that stopped the build. Append our
    # failing log to that.
    build_error_log = dist_dir / "logs/build_error.log"
    with build_error_log.open("a", encoding="utf-8") as error_log:
        error_log.write("\n")
        error_log.write(contents)


def launch_buildable(
    deps: ndk.deps.DependencyManager,
    workqueue: ndk.workqueue.AnyWorkQueue,
    log_dir: Path,
    debuggable: bool,
    skip_deps: bool,
    skip_modules: Set[ndk.builds.Module],
) -> None:
    # If args.skip_deps is true, we could get into a case where we just
    # dequeued the only module that was still building and the only
    # items in get_buildable() are modules that will be skipped.
    # Without this outer while loop, we'd mark the skipped dependencies
    # as complete and then complete the outer loop.  The workqueue
    # would be out of work and we'd exit.
    #
    # Avoid this by making sure that we queue all possible buildable
    # modules before we complete the loop.
    while deps.buildable_modules:
        for module in deps.get_buildable():
            if skip_deps and module in skip_modules:
                deps.complete(module)
                continue
            workqueue.add_task(launch_build, module, log_dir, debuggable)


@contextlib.contextmanager
def build_ui_context(debuggable: bool) -> Iterator[None]:
    if debuggable:
        yield
    else:
        console = ndk.ansi.get_console()
        with ndk.ansi.disable_terminal_echo(sys.stdin):
            with console.cursor_hide_context():
                yield


def wait_for_build(
    deps: ndk.deps.DependencyManager,
    workqueue: ndk.workqueue.AnyWorkQueue,
    dist_dir: Path,
    log_dir: Path,
    debuggable: bool,
    skip_deps: bool,
    skip_modules: Set[ndk.builds.Module],
) -> None:
    console = ndk.ansi.get_console()
    ui = ndk.ui.get_build_progress_ui(console, workqueue)
    with build_ui_context(debuggable):
        while not workqueue.finished():
            result, module = workqueue.get_result()
            if not result:
                ui.clear()
                print("Build failed: {}".format(module))
                log_build_failure(module.log_path(log_dir), dist_dir)
                sys.exit(1)
            elif not console.smart_console:
                ui.clear()
                print("Build succeeded: {}".format(module))

            deps.complete(module)
            launch_buildable(
                deps, workqueue, log_dir, debuggable, skip_deps, skip_modules
            )

            ui.draw()
        ui.clear()
        print("Build finished")


def check_ndk_symlink(ndk_dir: Path, src: Path, target: Path) -> None:
    """Check that the symlink's target is relative, exists, and points within
    the NDK installation.
    """
    if target.is_absolute():
        raise RuntimeError(f"Symlink {src} points to absolute path {target}")
    ndk_dir = ndk_dir.resolve()
    cur = src.parent.resolve()
    for part in target.parts:
        # (cur / part) might itself be a symlink. Its validity is checked from
        # the top-level scan, so it doesn't need to be checked here.
        cur = (cur / part).resolve()
        if not cur.exists():
            raise RuntimeError(f"Symlink {src} targets non-existent {cur}")
        if not cur.is_relative_to(ndk_dir):
            raise RuntimeError(f"Symlink {src} targets {cur} outside NDK {ndk_dir}")


def check_ndk_symlinks(ndk_dir: Path, host: Host) -> None:
    for path in ndk.paths.walk(ndk_dir):
        if not path.is_symlink():
            continue
        if host == Host.Windows64:
            # Symlinks aren't supported well enough on Windows. (e.g. They
            # require Developer Mode and/or special permissions. Cygwin
            # tools might create symlinks that non-Cygwin programs don't
            # recognize.)
            raise RuntimeError(f"Symlink {path} unexpected in Windows NDK")
        check_ndk_symlink(ndk_dir, path, path.readlink())


def build_ndk(
    modules: List[ndk.builds.Module],
    deps_only: Set[ndk.builds.Module],
    out_dir: Path,
    dist_dir: Path,
    args: argparse.Namespace,
) -> Path:
    build_context = ndk.builds.BuildContext(
        out_dir, dist_dir, ALL_MODULES, args.system, args.build_number
    )

    for module in modules:
        module.context = build_context

    log_dir = dist_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    ndk_dir = ndk.paths.get_install_path(out_dir, args.system)
    ndk_dir.mkdir(parents=True, exist_ok=True)

    deps = ndk.deps.DependencyManager(modules)
    if args.debuggable:
        workqueue: ndk.workqueue.AnyWorkQueue = ndk.workqueue.BasicWorkQueue()
    else:
        workqueue = ndk.workqueue.WorkQueue(args.jobs)
    try:
        launch_buildable(
            deps, workqueue, log_dir, args.debuggable, args.skip_deps, deps_only
        )
        wait_for_build(
            deps,
            workqueue,
            dist_dir,
            log_dir,
            args.debuggable,
            args.skip_deps,
            deps_only,
        )

        if deps.get_buildable():
            raise RuntimeError(
                "Builder stopped early. Modules are still "
                "buildable: {}".format(", ".join(str(deps.get_buildable())))
            )

        create_notice_file(ndk_dir / "NOTICE", ndk.builds.NoticeGroup.BASE)
        create_notice_file(
            ndk_dir / "NOTICE.toolchain", ndk.builds.NoticeGroup.TOOLCHAIN
        )
        check_ndk_symlinks(ndk_dir, args.system)
        return ndk_dir
    finally:
        workqueue.terminate()
        workqueue.join()


def build_ndk_for_cross_compile(out_dir: Path, args: argparse.Namespace) -> None:
    args = copy.deepcopy(args)
    args.system = Host.current()
    if args.system != Host.Linux:
        raise NotImplementedError
    module_names = NAMES_TO_MODULES.keys()
    modules, deps_only = get_modules_to_build(module_names)
    print("Building Linux modules: {}".format(" ".join([str(m) for m in modules])))
    build_ndk(modules, deps_only, out_dir, out_dir, args)


def create_ndk_symlink(out_dir: Path) -> None:
    this_host_ndk = ndk.paths.get_install_path()
    ndk_symlink = out_dir / this_host_ndk.name
    if not ndk_symlink.exists():
        os.symlink(this_host_ndk, ndk_symlink)


def get_directory_size(path: Path) -> int:
    du_str = subprocess.check_output(["du", "-sm", str(path)])
    match = re.match(r"^(\d+)", du_str.decode("utf-8"))
    if match is None:
        raise RuntimeError(f"Could not determine the size of {path}")
    size_str = match.group(1)
    return int(size_str)


def main() -> None:
    total_timer = ndk.timer.Timer()
    total_timer.start()

    args, module_names = parse_args()

    ensure_python_environment()

    if args.verbosity >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbosity == 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig()

    module_names.extend(args.modules)
    if not module_names:
        module_names = get_all_module_names()

    required_package_modules = set(get_all_module_names())
    have_required_modules = required_package_modules <= set(module_names)

    if args.package_tests is None:
        args.package_tests = args.package

    # TODO(danalbert): wine?
    # We're building the Windows packages from Linux, so we can't actually run
    # any of the tests from here.
    if args.system.is_windows or not have_required_modules:
        args.build_tests = False

    os.chdir(Path(__file__).resolve().parent.parent)

    # Set ANDROID_BUILD_TOP.
    if "ANDROID_BUILD_TOP" in os.environ:
        sys.exit(
            textwrap.dedent(
                """\
            Error: ANDROID_BUILD_TOP is already set in your environment.

            This typically means you are running in a shell that has launched a
            target in a platform build. The platform environment interferes
            with the NDK build environment, so the build cannot continue.

            Launch a new shell before building the NDK."""
            )
        )

    os.environ["ANDROID_BUILD_TOP"] = str(ndk.paths.android_path())

    out_dir = ndk.paths.get_out_dir()
    dist_dir = ndk.paths.get_dist_dir()

    print("Machine has {} CPUs".format(multiprocessing.cpu_count()))

    if args.system.is_windows and not args.skip_deps:
        # Since the Windows NDK is cross compiled, we need to build a Linux NDK
        # first so we can build components like libc++.
        build_ndk_for_cross_compile(Path(out_dir), args)

    modules, deps_only = get_modules_to_build(module_names)
    print(
        "Building modules: {}".format(
            " ".join(
                [str(m) for m in modules if not args.skip_deps or m not in deps_only]
            )
        )
    )

    build_timer = ndk.timer.Timer()
    with build_timer:
        ndk_dir = build_ndk(modules, deps_only, out_dir, dist_dir, args)
    installed_size = get_directory_size(ndk_dir)

    # Create a symlink to the NDK usable by this host in the root of the out
    # directory for convenience.
    create_ndk_symlink(out_dir)

    package_timer = ndk.timer.Timer()
    with package_timer:
        if args.package:
            print("Packaging NDK...")
            # NB: Purging of unwanted files (.pyc, Android.bp, etc) happens as
            # part of packaging. If testing is ever moved to happen before
            # packaging, ensure that the directory is purged before and after
            # building the tests.
            package_path = package_ndk(
                ndk_dir, out_dir, dist_dir, args.system, args.build_number
            )
            packaged_size_bytes = package_path.stat().st_size
            packaged_size = packaged_size_bytes // (2**20)

    good = True
    test_timer = ndk.timer.Timer()
    with test_timer:
        if args.build_tests:
            print("Building tests...")
            purge_unwanted_files(ndk_dir)
            good = build_ndk_tests(out_dir, dist_dir, args)
            print()  # Blank line between test results and timing data.

    total_timer.finish()

    print("")
    print("Installed size: {} MiB".format(installed_size))
    if args.package:
        print("Package size: {} MiB".format(packaged_size))
    print("Finished {}".format("successfully" if good else "unsuccessfully"))
    print("Build: {}".format(build_timer.duration))
    print("Packaging: {}".format(package_timer.duration))
    print("Testing: {}".format(test_timer.duration))
    print("Total: {}".format(total_timer.duration))

    subject = "NDK Build {}!".format("Passed" if good else "Failed")
    body = "Build finished in {}".format(total_timer.duration)
    ndk.notify.toast(subject, body)

    sys.exit(not good)


@contextlib.contextmanager
def _assign_self_to_new_process_group(fd: TextIO) -> Iterator[None]:
    # It seems the build servers run us in our own session, in which case we
    # get EPERM from `setpgrp`. No need to call this in that case because we
    # will already be the process group leader.
    if os.getpid() == os.getsid(os.getpid()):
        yield
        return

    if ndk.ansi.is_self_in_tty_foreground_group(fd):
        old_pgrp = os.tcgetpgrp(fd.fileno())
        os.tcsetpgrp(fd.fileno(), os.getpid())
        os.setpgrp()
        try:
            yield
        finally:
            os.tcsetpgrp(fd.fileno(), old_pgrp)
    else:
        os.setpgrp()
        yield


def _run_main_in_new_process_group() -> None:
    with _assign_self_to_new_process_group(sys.stdin):
        main()


if __name__ == "__main__":
    _run_main_in_new_process_group()
