#!/usr/bin/env python
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
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import collections
import contextlib
import copy
# pylint: disable=import-error,no-name-in-module
# https://github.com/PyCQA/pylint/issues/73
from distutils.dir_util import copy_tree
# pylint: enable=import-error,no-name-in-module
import inspect
import json
import logging
import multiprocessing
import os
from pathlib import Path
import pipes
import re
import shutil
import site
import stat
import subprocess
import sys
import textwrap
import traceback
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Set,
    TextIO,
    Tuple,
    Union,
)

import ndk.abis
import ndk.ansi
import ndk.autoconf
import ndk.builds
import ndk.cmake
import ndk.config
import ndk.deps
import ndk.ext.shutil
import ndk.file
from ndk.hosts import Host
import ndk.notify
import ndk.paths
from ndk.paths import ANDROID_DIR, NDK_DIR
import ndk.test.builder
import ndk.test.printers
import ndk.test.spec
import ndk.timer
from ndk.toolchains import ClangToolchain
import ndk.ui
import ndk.workqueue


def get_version_string(build_number: str) -> str:
    """Returns the version string for the current build."""
    return f'{ndk.config.major}.{ndk.config.hotfix}.{build_number}'


def _make_tar_package(package_path: str, base_dir: str, path: str) -> str:
    """Creates a tarball package for distribution.

    Args:
        package_path (string): Path (without extention) to the output archive.
        base_dir (string): Path to the directory from which to perform the
                           packaging (identical to tar's -C).
        path (string): Path to the directory to package.
    """
    has_pbzip2 = shutil.which('pbzip2') is not None
    if has_pbzip2:
        compress_arg = '--use-compress-prog=pbzip2'
    else:
        compress_arg = '-j'

    package_path = package_path + '.tar.bz2'
    cmd = ['tar', compress_arg, '-cf', package_path, '-C', base_dir, path]
    subprocess.check_call(cmd)
    return package_path


def _make_zip_package(package_path: Path, base_dir: Path, paths: List[str],
                      host: Host) -> Path:
    """Creates a zip package for distribution.

    Args:
        package_path: Path (without extension) to the output archive.
        base_dir: Path to the directory from which to perform the packaging
                  (identical to tar's -C).
        paths: Paths to files and directories to package, relative to base_dir.
        host: The host the package is being built for. Windows packages will
              flatten symlinks, but other platforms will not.
    """
    cwd = os.getcwd()
    package_path = package_path.with_suffix('.zip')

    args = ['zip', '-9qr', str(package_path)]
    if host != Host.Windows64:
        args.append('--symlinks')
    args.extend(paths)
    os.chdir(base_dir)
    try:
        subprocess.check_call(args)
        return package_path
    finally:
        os.chdir(cwd)


def purge_unwanted_files(ndk_dir: Path) -> None:
    """Removes unwanted files from the NDK install path."""

    for path in ndk.paths.walk(ndk_dir, directories=False):
        if path.suffix == '.pyc':
            path.unlink()
        elif path.name == 'Android.bp':
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
        textwrap.dedent("""\
        #!/bin/sh
        echo "The Android NDK is installed to the Contents/NDK directory of this application bundle."
        """))
    path.chmod(0o755)


def create_plist(plist: Path, version: str, entry_point_name: str) -> None:
    """Populates the NDK plist at the given location."""

    plist.write_text(
        textwrap.dedent(f"""\
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
        """))


def create_signer_metadata(package_dir: Path) -> None:
    """Populates the _codesign metadata directory for the ADRT signer.

    Args:
        package_dir: Path to the root of the directory that will be zipped for
                     the signer.
    """
    metadata_dir = package_dir / '_codesign'
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

    volumename_file = metadata_dir / 'volumename'
    volumename_file.write_text(f'Android NDK {ndk.config.release}')


def make_app_bundle(zip_path: Path, ndk_dir: Path, build_number: str,
                    build_dir: Path) -> None:
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
    package_dir = build_dir / 'bundle'
    app_directory_name = f'AndroidNDK{build_number}.app'
    bundle_dir = package_dir / app_directory_name
    if package_dir.exists():
        shutil.rmtree(package_dir)

    contents_dir = bundle_dir / 'Contents'
    entry_point_name = 'ndk'
    create_stub_entry_point(contents_dir / 'MacOS' / entry_point_name)

    bundled_ndk = contents_dir / 'NDK'
    shutil.copytree(ndk_dir, bundled_ndk)

    plist = contents_dir / 'Info.plist'
    create_plist(plist, get_version_string(build_number), entry_point_name)

    shutil.copy2(ndk_dir / 'source.properties',
                 package_dir / 'source.properties')
    create_signer_metadata(package_dir)
    _make_zip_package(zip_path, package_dir,
                      [p.name for p in package_dir.iterdir()], Host.Darwin)


def package_ndk(ndk_dir: Path, out_dir: Path, dist_dir: Path, host: Host,
                build_number: str) -> Path:
    """Packages the built NDK for distribution.

    Args:
        ndk_dir: Path to the built NDK.
        out_dir: Path to use for constructing any intermediate outputs.
        dist_dir: Path to place the built package in.
        host: Host the given NDK was built for.
        build_number: Build number to use in the package name.
    """
    package_name = f'android-ndk-{build_number}-{host.tag}'
    package_path = dist_dir / package_name

    purge_unwanted_files(ndk_dir)

    if host == Host.Darwin:
        bundle_name = f'android-ndk-{build_number}-app-bundle'
        bundle_path = dist_dir / bundle_name
        make_app_bundle(bundle_path, ndk_dir, build_number, out_dir)
    return _make_zip_package(package_path, ndk_dir.parent, [ndk_dir.name],
                             host)


def build_ndk_tests(out_dir: str, dist_dir: str,
                    args: argparse.Namespace) -> bool:
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
    test_src_dir = ndk.paths.ndk_path('tests')
    test_out_dir = os.path.join(out_dir, 'tests')

    site.addsitedir(os.path.join(ndk_dir, 'python-packages'))

    test_options = ndk.test.spec.TestOptions(
        test_src_dir, ndk_dir, test_out_dir, clean=True)

    printer = ndk.test.printers.StdoutPrinter()
    with open(ndk.paths.ndk_path('qa_config.json')) as config_file:
        test_config = json.load(config_file)

    test_spec = ndk.test.builder.test_spec_from_config(test_config)
    builder = ndk.test.builder.TestBuilder(
        test_spec, test_options, printer)

    report = builder.build()
    printer.print_summary(report)

    if report.successful and args.package:
        print('Packaging tests...')
        package_path = os.path.join(dist_dir, 'ndk-tests')
        _make_tar_package(package_path, out_dir, 'tests/dist')
    else:
        # Write out the result to logs/build_error.log so we can find the
        # failure easily on the build server.
        log_path = os.path.join(dist_dir, 'logs/build_error.log')
        with open(log_path, 'a') as error_log:
            error_log_printer = ndk.test.printers.FilePrinter(error_log)
            error_log_printer.print_summary(report)

    return report.successful


def install_file(file_name: str, src_dir: str, dst_dir: str) -> None:
    src_file = os.path.join(src_dir, file_name)
    dst_file = os.path.join(dst_dir, file_name)

    print('Copying {} to {}...'.format(src_file, dst_file))
    if os.path.isdir(src_file):
        _install_dir(src_file, dst_file)
    elif os.path.islink(src_file):
        _install_symlink(src_file, dst_file)
    else:
        _install_file(src_file, dst_file)


def _install_dir(src_dir: str, dst_dir: str) -> None:
    parent_dir = os.path.normpath(os.path.join(dst_dir, '..'))
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
    shutil.copytree(src_dir, dst_dir, symlinks=True)


def _install_symlink(src_file: str, dst_file: str) -> None:
    dirname = os.path.dirname(dst_file)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    link_target = os.readlink(src_file)
    os.symlink(link_target, dst_file)


def _install_file(src_file: str, dst_file: str) -> None:
    dirname = os.path.dirname(dst_file)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    # copy2 is just copy followed by copystat (preserves file metadata).
    shutil.copy2(src_file, dst_file)


class Clang(ndk.builds.Module):
    name = 'clang'
    path = Path('toolchains/llvm/prebuilt/{host}')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    @property
    def notices(self) -> Iterator[Path]:
        # TODO: Inject Host before this runs.
        for host in Host:
            ## XC-TODO: Check toolchain for current system ONLY
            if host != Host.current():
                continue
            yield ClangToolchain.path_for_host(host) / 'NOTICE'

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_path = self.get_install_path()
        bin_dir = install_path / 'bin'

        if install_path.exists():
            shutil.rmtree(install_path)
        if not install_path.parent.exists():
            install_path.parent.mkdir(parents=True)
        shutil.copytree(ClangToolchain.path_for_host(self.host), install_path,
                        symlinks=not self.host.is_windows)

        # clang-4053586 was patched in the prebuilts directory to add the
        # libc++ includes. These are almost certainly a different revision than
        # the NDK libc++, and may contain local changes that the NDK's don't
        # and vice versa. Best to just remove them for the time being since
        # that returns to the previous behavior.
        # https://github.com/android-ndk/ndk/issues/564#issuecomment-342307128
        shutil.rmtree(install_path / 'include')

        if self.host is Host.Linux:
            # The Linux toolchain wraps the compiler to inject some behavior
            # for the platform. They aren't used for every platform and we want
            # consistent behavior across platforms, and we also don't want the
            # extra cost they incur (fork/exec is cheap, but CreateProcess is
            # expensive), so remove them.
            (bin_dir / 'clang++.real').unlink()
            (bin_dir / 'clang++').unlink()
            (bin_dir / 'clang-cl').unlink()
            clang = install_path / 'bin/clang'
            (bin_dir / 'clang.real').rename(clang)
            make_symlink(bin_dir / 'clang++', Path('clang'))

        bin_ext = '.exe' if self.host.is_windows else ''
        if self.host.is_windows:
            # Remove LLD duplicates. We only need ld.lld. For non-Windows these
            # are all symlinks so we can keep them (and *need* to keep lld
            # since that's the real binary).
            # http://b/74250510
            (bin_dir / f'ld64.lld{bin_ext}').unlink()
            (bin_dir / f'lld{bin_ext}').unlink()
            (bin_dir / f'lld-link{bin_ext}').unlink()

        install_clanglib = install_path / 'lib64/clang'
        linux_prebuilt_path = ClangToolchain.path_for_host(Host.Linux)

        # Remove unused python scripts. They are not installed for Windows.
        # XC-TODO: This fold not exist.
        if self.host != Host.Windows64:
            python_bin_dir = install_path / 'lib64/python3' / 'bin'
            python_files_to_remove = [
                '2to3*', 'easy_install*', 'idle*', 'pip*',
                'pydoc*', 'python*-config',
            ]
            for file_pattern in python_files_to_remove:
                for pyfile in python_bin_dir.glob(file_pattern):
                    pyfile.unlink()

        # Remove lldb-argdumper in site-packages. libc++ is not available there.
        # People should use bin/lldb-argdumper instead.
        # XC-TODO: we ignore lldb now.
        # for pylib in (install_path / 'lib').glob('python*'):
        #    (pylib / f'site-packages/lldb/lldb-argdumper{bin_ext}').unlink()

        if self.host != Host.Linux:
            # We don't build target binaries as part of the Darwin or Windows
            # build. These toolchains need to get these from the Linux
            # prebuilts.
            #
            # The headers and libraries we care about are all in lib64/clang
            # for both toolchains, and those two are intended to be identical
            # between each host, so we can just replace them with the one from
            # the Linux toolchain.
            shutil.rmtree(install_clanglib)
            shutil.copytree(linux_prebuilt_path / 'lib64/clang',
                            install_clanglib)

        # The Clang prebuilts have the platform toolchain libraries in
        # lib64/clang. The libraries we want are in runtimes_ndk_cxx.
        ndk_runtimes = linux_prebuilt_path / 'runtimes_ndk_cxx'
        for version_dir in install_clanglib.iterdir():
            dst_lib_dir = version_dir / 'lib/linux'
            shutil.rmtree(dst_lib_dir)
            shutil.copytree(ndk_runtimes, dst_lib_dir)

            # Create empty libatomic.a stub libraries to keep -latomic working.
            # This is needed for backwards compatibility and might be useful if
            # upstream LLVM splits out the __atomic_* APIs from the builtins.
            for arch in ndk.abis.ALL_ARCHITECTURES:
                # Only the arch-specific subdir is on the linker search path.
                subdir = {
                    ndk.abis.Arch('arm'): 'arm',
                    ndk.abis.Arch('arm64'): 'aarch64',
                    ndk.abis.Arch('x86'): 'i386',
                    ndk.abis.Arch('x86_64'): 'x86_64',
                    ndk.abis.Arch('loongarch64'): 'loongarch64',
                }[arch]
                if arch == 'loongarch64':
                    (dst_lib_dir / subdir).mkdir(parents=True, exist_ok=True)
                (dst_lib_dir / subdir / 'libatomic.a').write_text(
                    textwrap.dedent("""\
                    /* The __atomic_* APIs are now in libclang_rt.builtins-*.a. They might
                       eventually be broken out into a separate library -- see llvm.org/D47606. */
                    """))

        # Also remove the other libraries that we installed, but they were only
        # installed on Linux.
        if self.host == Host.Linux:
            shutil.rmtree(install_path / 'runtimes_ndk_cxx')

        # Remove CMake package files that should not be exposed.
        # For some reason the LLVM install includes CMake modules that expose
        # its internal APIs. We want to purge these so apps don't accidentally
        # depend on them. See http://b/142327416 for more info.
        shutil.rmtree(install_path / 'lib64/cmake')

        # Remove libc++.a and libc++abi.a on Darwin. Now that these files are
        # universal binaries, they break notarization. Maybe it is possible to
        # fix notarization by using ditto to preserve APFS extended attributes.
        # See https://developer.apple.com/forums/thread/126038.
        if self.host == Host.Darwin:
            (install_path / 'lib64/libc++.a').unlink()
            (install_path / 'lib64/libc++abi.a').unlink()


def get_binutils_prebuilt_path(host: Host, arch: ndk.abis.Arch) -> Path:
    if host == Host.Windows64:
        host_dir_name = 'win64'
    else:
        host_dir_name = host.value

    prebuilt_path = (ANDROID_DIR / 'prebuilts/ndk/binutils' / host_dir_name /
                     f'binutils-{arch}-{host_dir_name}')
    if not prebuilt_path.is_dir():
        raise RuntimeError(
            f'Could not find prebuilt binutils at {prebuilt_path}')
    return prebuilt_path


def versioned_so(host: Host, lib: str, version: str) -> str:
    """Returns the formatted versioned library for the given host.

    >>> versioned_so(Host.Darwin, 'libfoo', '0')
    'libfoo.0.dylib'
    >>> versioned_so(Host.Linux, 'libfoo', '0')
    'libfoo.so.0'
    """
    if host == Host.Darwin:
        return f'{lib}.{version}.dylib'
    elif host == Host.Linux:
        return f'{lib}.so.{version}'
    raise ValueError(f'Unsupported host: {host}')


class ShaderTools(ndk.builds.CMakeModule):
    name = 'shader-tools'
    src = ANDROID_DIR / 'external' / 'shaderc' / 'shaderc'
    path = Path('shader-tools/{host}')
    run_ctest = True
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {'clang'}

    @property
    def notices(self) -> Iterator[Path]:
        base = ANDROID_DIR / 'external/shaderc'
        shaderc_dir = base / 'shaderc'
        glslang_dir = base / 'glslang'
        spirv_dir = base / 'spirv-headers'
        yield shaderc_dir / 'LICENSE'
        yield shaderc_dir / 'third_party/LICENSE.spirv-tools'
        yield glslang_dir / 'LICENSE.txt'
        yield spirv_dir / 'LICENSE'

    @property
    def defines(self) -> Dict[str, str]:
        gtest_dir = ANDROID_DIR / 'external' / 'googletest'
        effcee_dir = ANDROID_DIR / 'external' / 'effcee'
        re2_dir = ANDROID_DIR / 'external' / 'regex-re2'
        spirv_headers_dir = self.src.parent / 'spirv-headers'
        defines = {
            'SHADERC_EFFCEE_DIR': str(effcee_dir),
            'SHADERC_RE2_DIR': str(re2_dir),
            'SHADERC_GOOGLE_TEST_DIR': str(gtest_dir),
            'SHADERC_THIRD_PARTY_ROOT_DIR': str(self.src.parent),
            'EFFCEE_GOOGLETEST_DIR': str(gtest_dir),
            'EFFCEE_RE2_DIR': str(re2_dir),
            # SPIRV-Tools tests require effcee and re2.
            # Don't enable RE2 testing because it's long and not useful to us.
            'RE2_BUILD_TESTING': 'OFF',
            'SPIRV-Headers_SOURCE_DIR': str(spirv_headers_dir),
        }
        return defines

    @property
    def flags(self) -> List[str]:
        return super().flags + [
            '-Wno-unused-command-line-argument',
            '-fno-rtti',
            '-fno-exceptions',
        ]

    @property
    def ldflags(self) -> List[str]:
        ldflags = super().ldflags
        if self.host == Host.Linux:
            # Our libc++.so.1 re-exports libc++abi, and it will be installed in
            # the same directory as the executables.
            ldflags += ['-Wl,-rpath,\\$ORIGIN']
        if self.host == Host.Windows64:
            # TODO: The shaderc CMake files already pass these options for
            # gcc+mingw but not for clang+mingw. See
            # https://github.com/android/ndk/issues/1464.
            ldflags += ['-static', '-static-libgcc', '-static-libstdc++']
        return ldflags

    @property
    def env(self) -> Dict[str, str]:
        # Sets path for libc++, for ctest.
        if self.host == Host.Linux:
            return {'LD_LIBRARY_PATH': str(self._libcxx_dir)}
        return {}

    @property
    def _libcxx_dir(self) -> Path:
        return self.get_dep('clang').get_build_host_install() / 'lib64'

    @property
    def _libcxx(self) -> List[Path]:
        path = self._libcxx_dir
        if self.host == Host.Linux:
            return [path / 'libc++.so.1']
        return []

    def install(self) -> None:
        self.get_install_path().mkdir(parents=True, exist_ok=True)
        ext = '.exe' if self.host.is_windows else ''
        files_to_copy = [
            f'glslc{ext}', f'spirv-as{ext}', f'spirv-dis{ext}',
            f'spirv-val{ext}', f'spirv-cfg{ext}', f'spirv-opt{ext}',
            f'spirv-link{ext}', f'spirv-reduce{ext}'
        ]
        scripts_to_copy = ['spirv-lesspipe.sh']

        # Copy to install tree.
        for src in files_to_copy + scripts_to_copy:
            shutil.copy2(self.builder.install_directory / 'bin' / src,
                         self.get_install_path())

        if self.host.is_windows:
            for src in scripts_to_copy:
                # Convert line endings on scripts.
                # Do it in place to preserve executable permissions.
                subprocess.check_call(
                    ['unix2dos', '-o',
                     self.get_install_path() / src])

        # Symlink libc++ to install path.
        for lib in self._libcxx:
            symlink_name = self.get_install_path() / lib.name
            make_symlink(symlink_name, lib)


class Make(ndk.builds.CMakeModule):
    name = 'make'
    path = Path('prebuilt/{host}')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    src = ANDROID_DIR / 'toolchain/make'
    deps = {'clang'}

    @property
    def notices(self) -> Iterator[Path]:
        yield self.src / 'COPYING'


class Yasm(ndk.builds.AutoconfModule):
    name = 'yasm'
    path = Path('prebuilt/{host}')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    src = ANDROID_DIR / 'toolchain/yasm'

    @property
    def notices(self) -> Iterator[Path]:
        files = [
            'Artistic.txt',
            'BSD.txt',
            'COPYING',
            'GNU_GPL-2.0',
            'GNU_LGPL-2.0',
        ]
        for name in files:
            yield self.src / name


class NdkWhich(ndk.builds.FileModule):
    name = 'ndk-which'
    path = Path('prebuilt/{host}/bin/ndk-which')
    src = NDK_DIR / 'ndk-which'


class Python(ndk.builds.Module):
    """Module for host Python 2 to support GDB.

    This is now a prebuilt. Next time this or GDB breaks we'll be removing both
    and migrating the tools we ship with ndk-build to Python 3.
    """

    name = 'python'
    path = Path('prebuilt/{host}')
    PREBUILTS_BASE = ANDROID_DIR / 'prebuilts/ndk/python'
    notice = ANDROID_DIR / 'prebuilts/ndk/python/NOTICE'
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    def build(self) -> None:
        pass

    def install(self) -> None:
        copy_tree(str(self.PREBUILTS_BASE / self.host.tag),
                  str(self.get_install_path()))


class Toolbox(ndk.builds.Module):
    name = 'toolbox'
    path = Path('prebuilt/{host}/bin')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    notice = NDK_DIR / 'sources/host-tools/toolbox/NOTICE'

    def build_exe(self, src: Path, name: str) -> None:
        toolchain = ClangToolchain(self.host)
        cmd = [
            str(toolchain.cc),
            '-s',
            '-o',
            str(self.intermediate_out_dir / f'{name}.exe'),
            str(src),
        ] + toolchain.flags
        subprocess.run(cmd, check=True)

    def build(self) -> None:
        if not self.host.is_windows:
            print(f'Nothing to do for {self.host}')
            return

        self.intermediate_out_dir.mkdir(parents=True, exist_ok=True)

        src_dir = NDK_DIR / 'sources/host-tools/toolbox'
        self.build_exe(src_dir / 'echo_win.c', 'echo')
        self.build_exe(src_dir / 'cmp_win.c', 'cmp')

    def install(self) -> None:
        if not self.host.is_windows:
            print(f'Nothing to do for {self.host}')
            return

        install_dir = self.get_install_path()
        install_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(self.intermediate_out_dir / 'echo.exe', install_dir)
        shutil.copy2(self.intermediate_out_dir / 'cmp.exe', install_dir)

def install_exe(out_dir: str, install_dir: str, name: str, host: Host) -> None:
    ext = '.exe' if host.is_windows else ''
    exe_name = name + ext
    src = os.path.join(out_dir, exe_name)
    dst = os.path.join(install_dir, exe_name)

    ndk.ext.shutil.create_directory(install_dir)
    shutil.copy2(src, dst)


def make_linker_script(path: str, libs: List[str]) -> None:
    ndk.file.write_file(path, 'INPUT({})\n'.format(' '.join(libs)))


class Libcxx(ndk.builds.Module):
    name = 'libc++'
    src = ANDROID_DIR / 'toolchain/llvm-project/libcxx'
    path = Path('sources/cxx-stl/llvm-libc++')
    notice = src / 'LICENSE.TXT'
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {
        'base-toolchain',
        'libandroid_support',
        'ndk-build',
        'ndk-build-shortcut',
    }

    @property
    def obj_out(self) -> str:
        return os.path.join(self.out_dir, 'libcxx/obj')

    @property
    def lib_out(self) -> str:
        return os.path.join(self.out_dir, 'libcxx/libs')

    def build(self) -> None:
        ndk_build = os.path.join(
            self.get_dep('ndk-build').get_build_host_install(), 'ndk-build')
        #print('XC: ndk_build : ', ndk_build)
        bionic_path = ndk.paths.android_path('bionic')

        #print('XC: bionic_path: ', bionic_path)
        android_mk = self.src / 'Android.mk'
        application_mk = self.src / 'Application.mk'

        #print('XC: android_mk: ', android_mk)
        #print('XC: application_mk: ', application_mk)
        build_cmd = [
            'bash', ndk_build, f'-j{multiprocessing.cpu_count()}', 'V=1',

            # Since nothing in this build depends on libc++_static, we need to
            # name it to force it to build.
            'APP_MODULES=c++_shared c++_static',

            'BIONIC_PATH=' + bionic_path,

            # Tell ndk-build where all of our makefiles are and where outputs
            # should go. The defaults in ndk-build are only valid if we have a
            # typical ndk-build layout with a jni/{Android,Application}.mk.
            'NDK_PROJECT_PATH=null',
            f'APP_BUILD_SCRIPT={android_mk}',
            f'NDK_APPLICATION_MK={application_mk}',
            'NDK_OUT=' + self.obj_out,
            'NDK_LIBS_OUT=' + self.lib_out,

            # Make sure we don't pick up a cached copy.
            'LIBCXX_FORCE_REBUILD=true',
        ]

        print('Running: ' + ' '.join([pipes.quote(arg) for arg in build_cmd]))
        subprocess.check_call(build_cmd)

    def install(self) -> None:
        install_root = self.get_install_path()

        if os.path.exists(install_root):
            shutil.rmtree(install_root)
        os.makedirs(install_root)

        shutil.copy2(
            str(self.src / 'Android.mk'), install_root)
        shutil.copytree(
            str(self.src / 'include'),
            os.path.join(install_root, 'include'))
        shutil.copytree(self.lib_out, os.path.join(install_root, 'libs'))

        for abi in ndk.abis.ALL_ABIS:
            lib_dir = os.path.join(install_root, 'libs', abi)

            # The static libraries installed to the obj dir, not the lib dir.
            self.install_static_libs(lib_dir, abi)

            # Create linker scripts for the libraries we use so that we link
            # things properly even when we're not using ndk-build. The linker
            # will read the script in place of the library so that we link the
            # unwinder and other support libraries appropriately.
            platforms_meta = json.loads(
                ndk.file.read_file(ndk.paths.ndk_path('meta/platforms.json')))
            for api in range(platforms_meta['min'], platforms_meta['max'] + 1):
                if api < ndk.abis.min_api_for_abi(abi):
                    continue

    def install_static_libs(self, lib_dir: str, abi: ndk.abis.Abi) -> None:
        static_lib_dir = os.path.join(self.obj_out, 'local', abi)

        shutil.copy2(os.path.join(static_lib_dir, 'libc++abi.a'), lib_dir)
        shutil.copy2(os.path.join(static_lib_dir, 'libc++_static.a'), lib_dir)

        if abi in ndk.abis.LP32_ABIS:
            shutil.copy2(
                os.path.join(static_lib_dir, 'libandroid_support.a'), lib_dir)


class Platforms(ndk.builds.Module):
    name = 'platforms'
    path = Path('platforms')

    deps = {
        'clang',
    }

    min_supported_api = 16

    # These API levels had no new native APIs. The contents of these platforms
    # directories would be identical to the previous extant API level, so they
    # are not included in the NDK to save space.
    skip_apis = (20, 25)

    # Shared with the sysroot, though the sysroot NOTICE actually includes a
    # lot more licenses. Platforms and Sysroot are essentially a single
    # component that is split into two directories only temporarily, so this
    # will be the end state when we merge the two anyway.
    notice = ANDROID_DIR / 'prebuilts/ndk/platform/sysroot/NOTICE'

    intermediate_module = True

    prebuilts_path = ANDROID_DIR / 'prebuilts/ndk/platform'

    def src_path(self, *args: str) -> str:  # pylint: disable=no-self-use
        return ndk.paths.android_path('development/ndk/platforms', *args)

    def llvm_tool(self, tool: str) -> Path:
        path = Path(self.get_dep('clang').get_build_host_install())
        return path / f'bin/{tool}'

    # pylint: disable=no-self-use
    def libdir_name(self, arch: ndk.abis.Arch) -> str:
        if arch == 'x86_64':
            return 'lib64'
        else:
            return 'lib'
    # pylint: enable=no-self-use

    def get_apis(self) -> List[int]:
        apis: List[int] = []
        for path in (self.prebuilts_path / 'platforms').iterdir():
            name = path.name
            if not name.startswith('android-'):
                continue

            _, api_str = name.split('-')
            try:
                api = int(api_str)
                if api >= self.min_supported_api:
                    apis.append(api)
            except ValueError as ex:
                # Codenamed release like android-O, android-O-MR1, etc.
                # Codenamed APIs are not supported, since having
                # non-integer API directories breaks all kinds of tools, we
                # rename them when we check them in.
                raise ValueError(
                    f'No codenamed API is allowed: {api_str}\n'
                    'Use the update_platform.py tool from the '
                    'platform/prebuilts/ndk dev branch to remove or rename it.'
                ) from ex

        return sorted(apis)

    @staticmethod
    def get_arches(api: int) -> List[ndk.abis.Arch]:
        arches = [ndk.abis.Arch('arm'), ndk.abis.Arch('x86')]
        # All codenamed APIs are at 64-bit capable.
        if isinstance(api, str) or api >= 21:
            arches.extend([ndk.abis.Arch('arm64'), ndk.abis.Arch('x86_64')])
        if isinstance(api, str) or api >= 29:
            arches.extend([ndk.abis.Arch('loongarch64')])
        return arches

    def get_build_cmd(self, dst: str, srcs: List[str], api: int,
                      arch: ndk.abis.Arch,
                      build_number: Union[int, str]) -> List[str]:
        libc_includes = ndk.paths.ANDROID_DIR / 'bionic/libc'
        arch_common_includes = libc_includes / 'arch-common/bionic'

        cc = self.llvm_tool('clang')

        args = [
            str(cc),
            '-target',
            ndk.abis.clang_target(arch, api),
            '--sysroot',
            str(self.prebuilts_path / 'sysroot'),
            '-fuse-ld=lld',
            f'-I{libc_includes}',
            f'-I{arch_common_includes}',
            f'-DPLATFORM_SDK_VERSION={api}',
            f'-DABI_NDK_VERSION="{ndk.config.release}"',
            f'-DABI_NDK_BUILD_NUMBER="{build_number}"',
            '-O2',
            '-fpic',
            '-Wl,-r',
            '-no-pie',
            '-nostdlib',
            '-Wa,--noexecstack',
            '-Wl,-z,noexecstack',
            '-o',
            dst,
        ] + srcs

        if arch == ndk.abis.Arch('arm'):
            args.append('-mfpu=vfpv3-d16')
        elif arch == ndk.abis.Arch('arm64'):
            args.append('-mbranch-protection=standard')

        return args

    def check_elf_note(self, obj_file: str) -> None:
        # readelf is a cross platform tool, so arch doesn't matter.
        readelf = self.llvm_tool('llvm-readelf')
        out = subprocess.check_output([str(readelf), '--notes', obj_file])
        if 'Android' not in out.decode('utf-8'):
            raise RuntimeError(
                '{} does not contain NDK ELF note'.format(obj_file))

    def build_crt_object(self, dst: str, srcs: List[str], api: int,
                         arch: ndk.abis.Arch, build_number: Union[int, str],
                         defines: List[str]) -> None:
        cc_args = self.get_build_cmd(dst, srcs, api, arch, build_number)
        cc_args.extend(defines)

        print('Running: ' + ' '.join([pipes.quote(arg) for arg in cc_args]))
        subprocess.check_call(cc_args)

    def build_crt_objects(self, dst_dir: str, api: int,
                          arch: ndk.abis.Arch,
                          build_number: Union[int, str]) -> None:
        src_dir = ndk.paths.android_path('bionic/libc/arch-common/bionic')
        crt_brand = ndk.paths.ndk_path('sources/crt/crtbrand.S')

        objects = {
            'crtbegin_dynamic.o': [
                os.path.join(src_dir, 'crtbegin.c'),
                crt_brand,
            ],
            'crtbegin_so.o': [
                os.path.join(src_dir, 'crtbegin_so.c'),
                crt_brand,
            ],
            'crtbegin_static.o': [
                os.path.join(src_dir, 'crtbegin.c'),
                crt_brand,
            ],
            'crtend_android.o': [
                os.path.join(src_dir, 'crtend.S'),
            ],
            'crtend_so.o': [
                os.path.join(src_dir, 'crtend_so.S'),
            ],
        }

        for name, srcs in objects.items():
            dst_path = os.path.join(dst_dir, name)
            defs = []
            if name == 'crtbegin_static.o':
                # libc.a is always the latest version, so ignore the API level
                # setting for crtbegin_static.
                defs.append('-D_FORCE_CRT_ATFORK')
            self.build_crt_object(
                dst_path, srcs, api, arch, build_number, defs)
            if name.startswith('crtbegin'):
                self.check_elf_note(dst_path)

    def build(self) -> None:
        build_dir = os.path.join(self.out_dir, self.path)
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)

        for api in self.get_apis():
            if api in self.skip_apis:
                continue

            platform = 'android-{}'.format(api)
            for arch in self.get_arches(api):
                arch_name = 'arch-{}'.format(arch)
                dst_dir = os.path.join(build_dir, platform, arch_name)
                os.makedirs(dst_dir)
                assert self.context is not None
                self.build_crt_objects(dst_dir, api, arch,
                                       self.context.build_number)

    def install(self) -> None:
        build_dir = os.path.join(self.out_dir, self.path)
        install_dir = self.get_install_path()

        if os.path.exists(install_dir):
            shutil.rmtree(install_dir)
        os.makedirs(install_dir)

        for api in self.get_apis():
            if api in self.skip_apis:
                continue

            # Copy shared libraries from prebuilts/ndk/platform/platforms.
            platform = 'android-{}'.format(api)
            platform_src = self.prebuilts_path / 'platforms' / platform
            platform_dst = os.path.join(install_dir, 'android-{}'.format(api))
            shutil.copytree(platform_src, platform_dst)

            for arch in self.get_arches(api):
                arch_name = 'arch-{}'.format(arch)
                triple = ndk.abis.arch_to_triple(arch)

                # Install static libraries from prebuilts/ndk/platform/sysroot.
                # TODO: Determine if we can change the build system to use the
                # libraries directly from the sysroot directory rather than
                # duplicating all the libraries in platforms.
                lib_dir = self.prebuilts_path / 'sysroot/usr/lib' / triple
                libdir_name = self.libdir_name(arch)
                lib_dir_dst = os.path.join(
                    install_dir, platform, arch_name, 'usr', libdir_name)
                for name in os.listdir(lib_dir):
                    lib_src = os.path.join(lib_dir, name)
                    lib_dst = os.path.join(lib_dir_dst, name)
                    shutil.copy2(lib_src, lib_dst)

                if libdir_name == 'lib64':
                    # The Clang driver won't accept a sysroot that contains
                    # only a lib64. An empty lib dir is enough to convince it.
                    os.makedirs(os.path.join(
                        install_dir, platform, arch_name, 'usr/lib'))

                # Install the CRT objects that we just built.
                obj_dir = os.path.join(build_dir, platform, arch_name)
                for name in os.listdir(obj_dir):
                    obj_src = os.path.join(obj_dir, name)
                    obj_dst = os.path.join(lib_dir_dst, name)
                    # print ("XC copy crts: {} to obj_dst {}\n".format(obj_src, obj_dst))
                    shutil.copy2(obj_src, obj_dst)

        # https://github.com/android-ndk/ndk/issues/372
        for root, dirs, files in os.walk(install_dir):
            if not files and not dirs:
                with open(os.path.join(root, '.keep_dir'), 'w') as keep_file:
                    keep_file.write(
                        'This file forces git to keep the directory.')


class Gdb(ndk.builds.Module):
    """Module for multi-arch host GDB.

    This is now a prebuilt. GDB is no longer supported. Next time it breaks
    we'll be removing it.
    """

    name = 'gdb'
    path = Path('prebuilt')

    PREBUILTS_BASE = ANDROID_DIR / 'prebuilts/ndk/gdb'
    notice = ANDROID_DIR / 'prebuilts/ndk/gdb/NOTICE'
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    def build(self) -> None:
        pass

    @property
    def install_dir(self) -> Path:
        return Path(self.get_install_path())

    def gdbserver_for(self, arch: ndk.abis.Arch) -> Path:
        return self.PREBUILTS_BASE / f'android-{arch}'

    def install_gdbserver(self, arch: ndk.abis.Arch) -> None:
        gdbserver_dir = Path(f'android-{arch}/gdbserver')
        install_dir = self.install_dir / gdbserver_dir
        if install_dir.exists():
            shutil.rmtree(install_dir)
        shutil.copytree(self.PREBUILTS_BASE / gdbserver_dir, install_dir)

    def install_gdb(self) -> None:
        copy_tree(str(self.PREBUILTS_BASE / self.host.tag),
                  str(self.install_dir / self.host.tag))

    def install(self) -> None:
        """Installs GDB."""
        self.install_gdb()
        for arch in ndk.abis.ALL_ARCHITECTURES:
            self.install_gdbserver(arch)


class LibShaderc(ndk.builds.Module):
    name = 'libshaderc'
    path = Path('sources/third_party/shaderc')
    src = ANDROID_DIR / 'external/shaderc'
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN

    @property
    def notices(self) -> Iterator[Path]:
        shaderc_dir = self.src / 'shaderc'
        glslang_dir = self.src / 'glslang'
        yield shaderc_dir / 'LICENSE'
        yield glslang_dir / 'LICENSE.txt'
        yield shaderc_dir / 'third_party/LICENSE.spirv-tools'

    def build(self) -> None:
        pass

    def install(self) -> None:
        copies = [
            {
                'source_dir': os.path.join(self.src, 'shaderc'),
                'dest_dir': '',
                'files': [
                    'Android.mk', 'libshaderc/Android.mk',
                    'libshaderc_util/Android.mk',
                    'third_party/Android.mk',
                    'utils/update_build_version.py',
                    'CHANGES',
                ],
                'dirs': [
                    'libshaderc/include', 'libshaderc/src',
                    'libshaderc_util/include', 'libshaderc_util/src',
                ],
            },
            {
                'source_dir': os.path.join(self.src, 'spirv-tools'),
                'dest_dir': 'third_party/spirv-tools',
                'files': [
                    'utils/generate_grammar_tables.py',
                    'utils/generate_language_headers.py',
                    'utils/generate_registry_tables.py',
                    'utils/update_build_version.py',
                    'Android.mk',
                    'CHANGES',
                ],
                'dirs': ['include', 'source'],
            },
            {
                'source_dir': os.path.join(self.src, 'spirv-headers'),
                'dest_dir': 'third_party/spirv-tools/external/spirv-headers',
                'dirs': ['include'],
                'files': [
                    'include/spirv/1.0/spirv.py',
                    'include/spirv/1.1/spirv.py',
                    'include/spirv/1.2/spirv.py'
                    'include/spirv/uinified1/spirv.py'
                ],
            },
            {
                'source_dir': os.path.join(self.src, 'glslang'),
                'dest_dir': 'third_party/glslang',
                'files': [
                    'Android.mk',
                    'glslang/OSDependent/osinclude.h',
                    # Build version info is generated from the CHANGES.md file.
                    'CHANGES.md',
                    'build_info.h.tmpl',
                    'build_info.py',
                ],
                'dirs': [
                    'SPIRV',
                    'OGLCompilersDLL',
                    'glslang/GenericCodeGen',
                    'hlsl',
                    'glslang/HLSL',
                    'glslang/Include',
                    'glslang/MachineIndependent',
                    'glslang/OSDependent/Unix',
                    'glslang/Public',
                ],
            },
        ]

        default_ignore_patterns = shutil.ignore_patterns(
            "*CMakeLists.txt",
            "*.py",
            "*test.h",
            "*test.cc")

        install_dir = self.get_install_path()
        if install_dir.exists():
            shutil.rmtree(install_dir)

        for properties in copies:
            source_dir = properties['source_dir']
            assert isinstance(source_dir, str)
            assert isinstance(properties['dest_dir'], str)
            dest_dir = os.path.join(install_dir, properties['dest_dir'])
            for d in properties['dirs']:
                assert isinstance(d, str)
                src = os.path.join(source_dir, d)
                dst = os.path.join(dest_dir, d)
                print(src, " -> ", dst)
                shutil.copytree(src, dst,
                                ignore=default_ignore_patterns)
            for f in properties['files']:
                print(source_dir, ':', dest_dir, ":", f)
                # Only copy if the source file exists.  That way
                # we can update this script in anticipation of
                # source files yet-to-come.
                assert isinstance(f, str)
                if os.path.exists(os.path.join(source_dir, f)):
                    install_file(f, source_dir, dest_dir)
                else:
                    print(source_dir, ':', dest_dir, ":", f, "SKIPPED")


class CpuFeatures(ndk.builds.PackageModule):
    name = 'cpufeatures'
    path = Path('sources/android/cpufeatures')
    src = NDK_DIR / 'sources/android/cpufeatures'


class NativeAppGlue(ndk.builds.PackageModule):
    name = 'native_app_glue'
    path = Path('sources/android/native_app_glue')
    src = NDK_DIR / 'sources/android/native_app_glue'


class NdkHelper(ndk.builds.PackageModule):
    name = 'ndk_helper'
    path = Path('sources/android/ndk_helper')
    src = NDK_DIR / 'sources/android/ndk_helper'


class Gtest(ndk.builds.PackageModule):
    name = 'gtest'
    path = Path('sources/third_party/googletest')
    src = ANDROID_DIR / 'external/googletest/googletest'

    def install(self) -> None:
        super().install()
        # Docs are moved to top level directory.
        shutil.rmtree(self.get_install_path() / 'docs')


class Sysroot(ndk.builds.Module):
    name = 'sysroot'
    path = Path('sysroot')
    notice = ANDROID_DIR / 'prebuilts/ndk/platform/sysroot/NOTICE'
    intermediate_module = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_path = self.get_install_path()
        if install_path.exists():
            shutil.rmtree(install_path)
        path = ndk.paths.android_path('prebuilts/ndk/platform/sysroot')
        shutil.copytree(path, install_path)
        if self.host != 'linux':
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
                'usr/include/linux/netfilter_ipv4/ipt_ECN.h',
                'usr/include/linux/netfilter_ipv4/ipt_TTL.h',
                'usr/include/linux/netfilter_ipv6/ip6t_HL.h',
                'usr/include/linux/netfilter/xt_CONNMARK.h',
                'usr/include/linux/netfilter/xt_DSCP.h',
                'usr/include/linux/netfilter/xt_MARK.h',
                'usr/include/linux/netfilter/xt_RATEEST.h',
                'usr/include/linux/netfilter/xt_TCPMSS.h',
            ]
            for remove_path in remove_paths:
                os.remove(os.path.join(install_path, remove_path))

        ndk_version_h_path = os.path.join(install_path,
                                          'usr/include/android/ndk-version.h')
        with open(ndk_version_h_path, 'w') as ndk_version_h:
            major = ndk.config.major
            minor = ndk.config.hotfix
            beta = ndk.config.beta
            canary = '1' if ndk.config.canary else '0'
            assert self.context is not None

            ndk_version_h.write(textwrap.dedent(f"""\
                #pragma once

                /**
                 * Set to 1 if this is an NDK, unset otherwise. See
                 * https://android.googlesource.com/platform/bionic/+/master/docs/defines.md.
                 */
                #define __ANDROID_NDK__ 1

                /**
                 * Major version of this NDK.
                 *
                 * For example: 16 for r16.
                 */
                #define __NDK_MAJOR__ {major}

                /**
                 * Minor version of this NDK.
                 *
                 * For example: 0 for r16 and 1 for r16b.
                 */
                #define __NDK_MINOR__ {minor}

                /**
                 * Set to 0 if this is a release build, or 1 for beta 1,
                 * 2 for beta 2, and so on.
                 */
                #define __NDK_BETA__ {beta}

                /**
                 * Build number for this NDK.
                 *
                 * For a local development build of the NDK, this is -1.
                 */
                #define __NDK_BUILD__ {self.context.build_number}

                /**
                 * Set to 1 if this is a canary build, 0 if not.
                 */
                #define __NDK_CANARY__ {canary}
                """))


def write_clang_shell_script(wrapper_path: str, clang_name: str,
                             flags: List[str]) -> None:
    with open(wrapper_path, 'w') as wrapper:
        wrapper.write(textwrap.dedent("""\
            #!/bin/bash
            if [ "$1" != "-cc1" ]; then
                `dirname $0`/{clang} {flags} "$@"
            else
                # Target is already an argument.
                `dirname $0`/{clang} "$@"
            fi
        """.format(clang=clang_name, flags=' '.join(flags))))

    mode = os.stat(wrapper_path).st_mode
    os.chmod(wrapper_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_clang_batch_script(wrapper_path: str, clang_name: str,
                             flags: List[str]) -> None:
    with open(wrapper_path, 'w') as wrapper:
        wrapper.write(textwrap.dedent("""\
            @echo off
            setlocal
            call :find_bin
            if "%1" == "-cc1" goto :L

            set "_BIN_DIR=" && %_BIN_DIR%{clang} {flags} %*
            if ERRORLEVEL 1 exit /b 1
            goto :done

            :L
            rem Target is already an argument.
            set "_BIN_DIR=" && %_BIN_DIR%{clang} %*
            if ERRORLEVEL 1 exit /b 1
            goto :done

            :find_bin
            rem Accommodate a quoted arg0, e.g.: "clang"
            rem https://github.com/android-ndk/ndk/issues/616
            set _BIN_DIR=%~dp0
            exit /b

            :done
        """.format(clang=clang_name, flags=' '.join(flags))))


def write_clang_wrapper(install_dir: str, api: int, triple: str,
                        is_windows: bool) -> None:
    """Writes a target-specific Clang wrapper.

    This wrapper can be used to target the given architecture/API combination
    without needing to specify -target. These obviate the need for standalone
    toolchains.

    Ideally these would be symlinks rather than wrapper scripts to avoid the
    unnecessary indirection (Clang will infer its default target based on
    argv[0]), but the SDK manager can't install symlinks and Windows only
    allows administrators to create them.
    """
    exe_suffix = '.exe' if is_windows else ''

    if triple.startswith('arm-linux'):
        triple = 'armv7a-linux-androideabi'

    wrapper_path = os.path.join(install_dir, '{}{}-clang'.format(triple, api))
    wrapperxx_path = wrapper_path + '++'

    flags = ['--target={}{}'.format(triple, api)]

    # TODO: Hoist into the driver.
    if triple.startswith('i686') and api < 24:
        flags.append('-mstackrealign')

    # Write shell scripts even for Windows to support WSL and Cygwin.
    write_clang_shell_script(wrapper_path, 'clang' + exe_suffix, flags)
    write_clang_shell_script(wrapperxx_path, 'clang++' + exe_suffix, flags)
    if is_windows:
        write_clang_batch_script(wrapper_path + '.cmd', 'clang' + exe_suffix,
                                 flags)
        write_clang_batch_script(wrapperxx_path + '.cmd',
                                 'clang++' + exe_suffix, flags)


class BaseToolchain(ndk.builds.Module):
    """The subset of the toolchain needed to build other toolchain components.

    libc++ is built using this toolchain, and the full toolchain requires
    libc++. The toolchain is split into BaseToolchain and Toolchain to break
    the cyclic dependency.
    """

    name = 'base-toolchain'
    # This is installed to the Clang location to avoid migration pain.
    path = Path('toolchains/llvm/prebuilt/{host}')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {
        'clang',
        'libandroid_support',
        'make',
        'platforms',
        'sysroot',
        'system-stl',
        'yasm',
    }

    @property
    def notices(self) -> Iterator[Path]:
        yield from Clang().notices
        yield from Yasm().notices
        yield from LibAndroidSupport().notices
        yield from Platforms().notices
        yield from Sysroot().notices
        yield from SystemStl().notices
        yield ANDROID_DIR / 'toolchain/binutils/binutils-2.27/gas/COPYING'

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_dir = self.get_install_path()
        yasm_dir = self.get_dep('yasm').get_install_path()
        libandroid_support_dir = self.get_dep(
            'libandroid_support').get_install_path()
        platforms_dir = self.get_dep('platforms').get_install_path()
        sysroot_dir = self.get_dep('sysroot').get_install_path()
        system_stl_dir = self.get_dep('system-stl').get_install_path()

        copy_tree(str(sysroot_dir), str(install_dir / 'sysroot'))

        exe = '.exe' if self.host.is_windows else ''
        shutil.copy2(
            os.path.join(yasm_dir, 'bin', 'yasm' + exe),
            os.path.join(install_dir, 'bin'))

        bin_dir = Path(install_dir) / 'bin'
        lld = bin_dir / f'ld.lld{exe}'
        new_bin_ld = bin_dir / f'ld{exe}'

        shutil.copyfile(lld, new_bin_ld)
        shutil.copystat(lld, new_bin_ld)

        for arch in ndk.abis.ALL_ARCHITECTURES:
            binutils_dir = get_binutils_prebuilt_path(self.host, arch)
            triple = ndk.abis.arch_to_triple(arch)

            gas_name = f'{triple}-as{exe}'
            gas = binutils_dir / 'bin' / gas_name
            shutil.copy2(gas, bin_dir / gas_name)
            triple_bin_dir = Path(install_dir) / triple / 'bin'
            triple_bin_dir.mkdir(parents=True)
            if self.host is Host.Windows64:
                shutil.copy2(gas, triple_bin_dir / 'as.exe')
            else:
                make_symlink(triple_bin_dir / 'as', bin_dir / gas_name)

            # Without a GCC lib directory, Clang will not consider the
            # toolchain to be a binutils directory, so won't find GAS when
            # using -fno-integrated-as. To be considered a GCC directory it
            # must contain a file named crtbegin.o, but the contents are
            # irrelevant.
            # https://github.com/android/ndk/issues/1569
            gcc_lib_dir = install_dir / 'lib/gcc' / triple / '4.9.x'
            gcc_lib_dir.mkdir(parents=True)
            (gcc_lib_dir / 'crtbegin.o').write_text(
                'This file cannot be used but is needed for Clang to find GAS.'
            )

        platforms = self.get_dep('platforms')
        assert isinstance(platforms, Platforms)
        for api in platforms.get_apis():
            if api in Platforms.skip_apis:
                continue

            platform = 'android-{}'.format(api)
            for arch in platforms.get_arches(api):
                triple = ndk.abis.arch_to_triple(arch)
                arch_name = 'arch-{}'.format(arch)
                lib_dir = 'lib64' if arch == 'x86_64' else 'lib'
                src_dir = os.path.join(platforms_dir, platform, arch_name,
                                       'usr', lib_dir)
                dst_dir = os.path.join(install_dir, 'sysroot/usr/lib', triple,
                                       str(api))
                shutil.copytree(src_dir, dst_dir)

                # XC-TODO:
                if arch == 'loongarch64':
                    gcc_lib_dir = install_dir / 'lib/gcc' / triple / '4.9.x'
                    print ("XC: gcc_lib_dir :  \n", gcc_lib_dir)
                    shutil.copy2(os.path.join(src_dir, 'crtbegin_so.o'), gcc_lib_dir / 'crtbegin_so.o')
                    shutil.copy2(os.path.join(src_dir, 'crtend_so.o'), gcc_lib_dir / 'crtend_so.o')
                    shutil.copy2(os.path.join(src_dir, 'crtbegin_dynamic.o'), gcc_lib_dir / 'crtbegin_dynamic.o')
                    shutil.copy2(os.path.join(src_dir, 'crtend_android.o'), gcc_lib_dir / 'crtend_android.o')
                    shutil.copy2(os.path.join(src_dir, 'crtbegin_static.o'), gcc_lib_dir)

                # TODO: Remove duplicate static libraries from this directory.
                # We already have them in the version-generic directory.

                write_clang_wrapper(
                    os.path.join(install_dir, 'bin'), api, triple,
                    self.host.is_windows)

        # Clang searches for libstdc++ headers at $GCC_PATH/../include/c++. It
        # maybe be worth adding a search for the same path within the usual
        # sysroot location to centralize these, or possibly just remove them
        # from the NDK since they aren't particularly useful anyway.
        system_stl_hdr_dir = os.path.join(install_dir, 'include/c++')
        os.makedirs(system_stl_hdr_dir)
        system_stl_inc_src = os.path.join(system_stl_dir, 'include')
        system_stl_inc_dst = os.path.join(system_stl_hdr_dir, '4.9.x')
        shutil.copytree(system_stl_inc_src, system_stl_inc_dst)

        # $SYSROOT/usr/local/include comes before $SYSROOT/usr/include, so we
        # can use that for libandroid_support's headers. Puting them here
        # *does* mean that libandroid_support's headers get used even when
        # we're not using libandroid_support, but they should be a no-op for
        # android-21+ and in the case of pre-21 without libandroid_support
        # (libstdc++), we're only degrading the UX; the user will get a linker
        # error instead of a compiler error.
        support_hdr_dir = os.path.join(install_dir, 'sysroot/usr/local')
        os.makedirs(support_hdr_dir)
        support_inc_src = os.path.join(libandroid_support_dir, 'include')
        support_inc_dst = os.path.join(support_hdr_dir, 'include')
        shutil.copytree(support_inc_src, support_inc_dst)


class Vulkan(ndk.builds.Module):
    name = 'vulkan'
    path = Path('sources/third_party/vulkan')
    notice = ANDROID_DIR / 'external/vulkan-headers/NOTICE'

    def build(self) -> None:
        pass

    def install(self) -> None:
        default_ignore_patterns = shutil.ignore_patterns(
            '*CMakeLists.txt',
            '*test.cc',
            'linux',
            'windows')

        source_dir = ANDROID_DIR / 'external/vulkan-headers'
        dest_dir = self.get_install_path() / 'src'
        for d in ['include', 'registry']:
            src = source_dir / d
            dst = dest_dir / d
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst,
                            ignore=default_ignore_patterns)

        android_mk = dest_dir / 'build-android/jni/Android.mk'
        android_mk.parent.mkdir(parents=True, exist_ok=True)
        url = "https://github.com/KhronosGroup/Vulkan-ValidationLayers"
        android_mk.write_text(textwrap.dedent(f"""\
            $(warning The Vulkan Validation Layers are now distrubted on \\
                GitHub. See {url} for more information.)
            """))


class Toolchain(ndk.builds.Module):
    """The complete toolchain.

    BaseToolchain installs the core of the toolchain. This module installs the
    STL to that toolchain.
    """

    name = 'toolchain'
    # This is installed to the Clang location to avoid migration pain.
    path = Path('toolchains/llvm/prebuilt/{host}')
    notice_group = ndk.builds.NoticeGroup.TOOLCHAIN
    deps = {
        'base-toolchain',
        'libc++',
        'libc++abi',
        'platforms',
    }

    @property
    def notices(self) -> Iterator[Path]:
        yield from Libcxx().notices
        yield from Libcxxabi().notices

    def build(self) -> None:
        pass

    def install(self) -> None:
        install_dir = self.get_install_path()
        libcxx_dir = self.get_dep('libc++').get_install_path()
        libcxxabi_dir = self.get_dep('libc++abi').get_install_path()

        libcxx_hdr_dir = os.path.join(install_dir, 'sysroot/usr/include/c++')
        os.makedirs(libcxx_hdr_dir)
        libcxx_inc_src = os.path.join(libcxx_dir, 'include')
        libcxx_inc_dst = os.path.join(libcxx_hdr_dir, 'v1')
        shutil.copytree(libcxx_inc_src, libcxx_inc_dst)

        libcxxabi_inc_src = os.path.join(libcxxabi_dir, 'include')
        copy_tree(libcxxabi_inc_src, libcxx_inc_dst)

        for arch in ndk.abis.ALL_ARCHITECTURES:
            triple = ndk.abis.arch_to_triple(arch)
            abi, = ndk.abis.arch_to_abis(arch)
            libcxx_lib_dir = os.path.join(libcxx_dir, 'libs', abi)
            sysroot_dst = os.path.join(install_dir, 'sysroot/usr/lib', triple)

            libs = [
                'libc++_shared.so',
                'libc++_static.a',
                'libc++abi.a',
            ]
            if abi in ndk.abis.LP32_ABIS:
                libs.append('libandroid_support.a')

            for lib in libs:
                shutil.copy2(os.path.join(libcxx_lib_dir, lib), sysroot_dst)

        platforms = self.get_dep('platforms')
        assert isinstance(platforms, Platforms)
        for api in platforms.get_apis():
            if api in Platforms.skip_apis:
                continue

            for arch in platforms.get_arches(api):
                triple = ndk.abis.arch_to_triple(arch)
                dst_dir = os.path.join(install_dir, 'sysroot/usr/lib', triple,
                                       str(api))

                # Also install a libc++.so and libc++.a linker script per API
                # level. We need this to be done on a per-API level basis
                # because libandroid_support is only used on pre-21 API levels.
                static_script = ['-lc++_static', '-lc++abi']
                shared_script = ['-lc++_shared']
                if api < 21:
                    # The ordering here is funky because of interdependencies
                    # between libandroid_support and libc++abi.
                    # libandroid_support needs new/delete from libc++abi but
                    # libc++abi needs posix_memalign from libandroid_support.
                    static_script.extend([
                        '-landroid_support',
                        '-lc++abi',
                        # TODO: Remove once API 16 is no longer supported.
                        '-landroid_support',
                    ])
                    shared_script.insert(0, '-landroid_support')

                libcxx_so_path = os.path.join(dst_dir, 'libc++.so')
                with open(libcxx_so_path, 'w') as script:
                    script.write('INPUT({})'.format(' '.join(shared_script)))

                libcxx_a_path = os.path.join(dst_dir, 'libc++.a')
                with open(libcxx_a_path, 'w') as script:
                    script.write('INPUT({})'.format(' '.join(static_script)))
                # XC-TODO:
                if arch == 'loongarch64':
                    gcc_lib_dir = install_dir / 'lib/gcc' / triple / '4.9.x'
                    shutil.copy2(os.path.join(dst_dir, 'libc++.a'), gcc_lib_dir)
                    shutil.copy2(os.path.join(dst_dir, 'liblog.so'), gcc_lib_dir)
                    shutil.copy2(os.path.join(dst_dir, 'libandroid.so'), gcc_lib_dir)
                    shutil.copy2(os.path.join(dst_dir, 'libOpenSLES.so'), gcc_lib_dir)


def make_format_value(value: Any) -> Any:
    if isinstance(value, list):
        return ' '.join(value)
    return value


def var_dict_to_make(var_dict: Dict[str, Any]) -> str:
    lines = []
    for name, value in var_dict.items():
        lines.append('{} := {}'.format(name, make_format_value(value)))
    return os.linesep.join(lines)


def cmake_format_value(value: Any) -> Any:
    if isinstance(value, list):
        return ';'.join(value)
    return value


def var_dict_to_cmake(var_dict: Dict[str, Any]) -> str:
    lines = []
    for name, value in var_dict.items():
        lines.append('set({} "{}")'.format(name, cmake_format_value(value)))
    return os.linesep.join(lines)


def abis_meta_transform(metadata: Dict) -> Dict[str, Any]:
    default_abis = []
    deprecated_abis = []
    lp32_abis = []
    lp64_abis = []
    abi_infos = {}
    for abi, abi_data in metadata.items():
        bitness = abi_data['bitness']
        if bitness == 32:
            lp32_abis.append(abi)
        elif bitness == 64:
            lp64_abis.append(abi)
        else:
            raise ValueError('{} bitness is unsupported value: {}'.format(
                abi, bitness))

        if abi_data['default']:
            default_abis.append(abi)

        if abi_data['deprecated']:
            deprecated_abis.append(abi)

        proc = abi_data['proc']
        arch = abi_data['arch']
        triple = abi_data['triple']
        llvm_triple = abi_data['llvm_triple']
        abi_infos[f'NDK_ABI_{abi}_PROC'] = proc
        abi_infos[f'NDK_ABI_{abi}_ARCH'] = arch
        abi_infos[f'NDK_ABI_{abi}_TRIPLE'] = triple
        abi_infos[f'NDK_ABI_{abi}_LLVM_TRIPLE'] = llvm_triple
        abi_infos[f'NDK_PROC_{proc}_ABI'] = abi
        abi_infos[f'NDK_ARCH_{arch}_ABI'] = abi

    meta_vars = {
        'NDK_DEFAULT_ABIS': sorted(default_abis),
        'NDK_DEPRECATED_ABIS': sorted(deprecated_abis),
        'NDK_KNOWN_DEVICE_ABI32S': sorted(lp32_abis),
        'NDK_KNOWN_DEVICE_ABI64S': sorted(lp64_abis),
        'NDK_KNOWN_DEVICE_ABIS': sorted(lp32_abis + lp64_abis),
    }
    meta_vars.update(abi_infos)

    return meta_vars


def platforms_meta_transform(metadata: Dict) -> Dict[str, Any]:
    meta_vars = {
        'NDK_MIN_PLATFORM_LEVEL': metadata['min'],
        'NDK_MAX_PLATFORM_LEVEL': metadata['max'],
    }

    for src, dst in metadata['aliases'].items():
        name = 'NDK_PLATFORM_ALIAS_{}'.format(src)
        value = 'android-{}'.format(dst)
        meta_vars[name] = value
    return meta_vars


def system_libs_meta_transform(metadata: Dict) -> Dict[str, Any]:
    # This file also contains information about the first supported API level
    # for each library. We could use this to provide better diagnostics in
    # ndk-build, but currently do not.
    return {'NDK_SYSTEM_LIBS': sorted(metadata.keys())}


class NdkBuild(ndk.builds.PackageModule):
    name = 'ndk-build'
    path = Path('build')
    src = NDK_DIR / 'build'
    notice = NDK_DIR / 'NOTICE'

    deps = {
        'meta',
        'clang',
    }

    def install(self) -> None:
        super().install()

        self.install_ndk_version_makefile()
        self.generate_cmake_compiler_id()

        self.generate_language_specific_metadata('abis', abis_meta_transform)

        self.generate_language_specific_metadata('platforms',
                                                 platforms_meta_transform)

        self.generate_language_specific_metadata('system_libs',
                                                 system_libs_meta_transform)

    def install_ndk_version_makefile(self) -> None:
        """Generates a version.mk for ndk-build."""
        version_mk = Path(self.get_install_path()) / 'core/version.mk'
        version_mk.write_text(textwrap.dedent(f"""\
            NDK_MAJOR := {ndk.config.major}
            NDK_MINOR := {ndk.config.hotfix}
            NDK_BETA := {ndk.config.beta}
            NDK_CANARY := {str(ndk.config.canary).lower()}
            """))


    def get_clang_version(self, clang: Path) -> str:
        """Invokes Clang to determine its version string."""
        result = subprocess.run([str(clang), '--version'],
                                capture_output=True,
                                encoding='utf-8',
                                check=True)
        version_line = result.stdout.splitlines()[0]
        # Format of the version line is:
        # Android ($BUILD, based on $REV) clang version x.y.z ($GIT_URL $SHA)
        match = re.search(r'clang version ([0-9.]+)\s', version_line)
        if match is None:
            raise RuntimeError(
                f'Could not find Clang version in:\n{result.stdout}')
        return match.group(1)

    def generate_cmake_compiler_id(self) -> None:
        """Generates compiler ID information for old versions of CMake."""
        compiler_id_file = (Path(self.get_install_path()) /
                            'cmake/compiler_id.cmake')
        clang_prebuilts = Path(self.get_dep('clang').get_build_host_install())
        clang = clang_prebuilts / 'bin/clang'
        clang_version = self.get_clang_version(clang)

        compiler_id_file.write_text(textwrap.dedent(f"""\
            # The file is automatically generated when the NDK is built.
            set(CMAKE_C_COMPILER_VERSION {clang_version})
            set(CMAKE_CXX_COMPILER_VERSION {clang_version})
            """))

    def generate_language_specific_metadata(
            self, name: str, func: Callable[[Dict], Dict[str, Any]]) -> None:
        install_path = self.get_install_path()
        json_path = os.path.join(
            self.get_dep('meta').get_install_path(), name + '.json')
        meta = json.loads(ndk.file.read_file(json_path))
        meta_vars = func(meta)

        ndk.file.write_file(
            os.path.join(install_path, 'core/{}.mk'.format(name)),
            var_dict_to_make(meta_vars))
        ndk.file.write_file(
            os.path.join(install_path, 'cmake/{}.cmake'.format(name)),
            var_dict_to_cmake(meta_vars))


class PythonPackages(ndk.builds.PackageModule):
    name = 'python-packages'
    path = Path('python-packages')
    src = ANDROID_DIR / 'development/python-packages'


class SystemStl(ndk.builds.PackageModule):
    name = 'system-stl'
    path = Path('sources/cxx-stl/system')
    src = NDK_DIR / 'sources/cxx-stl/system'


class LibAndroidSupport(ndk.builds.PackageModule):
    name = 'libandroid_support'
    path = Path('sources/android/support')
    src = NDK_DIR / 'sources/android/support'


class Libcxxabi(ndk.builds.PackageModule):
    name = 'libc++abi'
    path = Path('sources/cxx-stl/llvm-libc++abi')
    src = ANDROID_DIR / 'toolchain/llvm-project/libcxxabi'


class SimplePerf(ndk.builds.Module):
    name = 'simpleperf'
    path = Path('simpleperf')
    notice = ANDROID_DIR / 'prebuilts/simpleperf/NOTICE'

    def build(self) -> None:
        pass

    def install(self) -> None:
        print('Installing simpleperf...')
        install_dir = self.get_install_path()
        if install_dir.exists():
            shutil.rmtree(install_dir)
        install_dir.mkdir(parents=True)

        simpleperf_path = ndk.paths.android_path('prebuilts/simpleperf')
        dirs = ['doc', 'inferno', 'bin/android', 'app_api', 'purgatorio']
        host_bin_dir = 'windows' if self.host.is_windows else self.host.value
        dirs.append(os.path.join('bin/', host_bin_dir))
        for d in dirs:
            shutil.copytree(os.path.join(simpleperf_path, d),
                            os.path.join(install_dir, d))

        for item in os.listdir(simpleperf_path):
            should_copy = False
            if item.endswith('.py') and item not in ['update.py', 'test.py',
                                                     'test_monitor.py']:
                should_copy = True
            elif item == 'report_html.js':
                should_copy = True
            elif item == 'inferno.sh' and not self.host.is_windows:
                should_copy = True
            elif item == 'inferno.bat' and self.host.is_windows:
                should_copy = True
            if should_copy:
                shutil.copy2(os.path.join(simpleperf_path, item), install_dir)

        shutil.copy2(os.path.join(simpleperf_path, 'ChangeLog'), install_dir)


class RenderscriptLibs(ndk.builds.PackageModule):
    name = 'renderscript-libs'
    path = Path('sources/android/renderscript')
    src = NDK_DIR / 'sources/android/renderscript'


class RenderscriptToolchain(ndk.builds.Module):
    name = 'renderscript-toolchain'
    path = Path('toolchains/renderscript/prebuilt/{host}')

    @property
    def notices(self) -> Iterator[Path]:
        base = ANDROID_DIR / 'prebuilts/renderscript/host'
        #yield base / 'darwin-x86/current/NOTICE'
        yield base / 'linux-x86/current/NOTICE'
        #yield base / 'windows-x86/current/NOTICE'

    def build(self) -> None:
        pass

    @property
    def prebuilt_directory(self) -> Path:
        tag = {
            Host.Darwin: 'darwin-x86',
            Host.Linux: 'linux-x86',
            Host.Windows64: 'windows-x86',
        }[self.host]
        return ANDROID_DIR / 'prebuilts/renderscript/host' / tag / 'current'

    def install(self) -> None:
        install_path = self.get_install_path(self.host)
        ndk.builds.install_directory(self.prebuilt_directory, install_path)


class Changelog(ndk.builds.FileModule):
    name = 'changelog'
    path = Path('CHANGELOG.md')
    src = NDK_DIR / f'docs/changelogs/Changelog-r{ndk.config.major}.md'
    no_notice = True


class NdkGdb(ndk.builds.MultiFileModule):
    name = 'ndk-gdb'
    path = Path('prebuilt/{host}/bin')
    notice = NDK_DIR / 'NOTICE'

    @property
    def files(self) -> Iterator[Path]:
        yield NDK_DIR / 'ndk-gdb'
        yield NDK_DIR / 'ndk-gdb.py'

        if self.host.is_windows:
            yield NDK_DIR / 'ndk-gdb.cmd'


class NdkGdbShortcut(ndk.builds.ScriptShortcutModule):
    name = 'ndk-gdb-shortcut'
    path = Path('ndk-gdb')
    script = Path('prebuilt/{host}/bin/ndk-gdb')
    windows_ext = '.cmd'


class NdkLldbShortcut(ndk.builds.ScriptShortcutModule):
    name = 'ndk-lldb-shortcut'
    path = Path('ndk-lldb')
    script = Path('prebuilt/{host}/bin/ndk-gdb')
    windows_ext = '.cmd'


class NdkStack(ndk.builds.MultiFileModule):
    name = 'ndk-stack'
    path = Path('prebuilt/{host}/bin')
    notice = NDK_DIR / 'NOTICE'

    @property
    def files(self) -> Iterator[Path]:
        yield NDK_DIR / 'ndk-stack'
        yield NDK_DIR / 'ndk-stack.py'

        if self.host.is_windows:
            yield NDK_DIR / 'ndk-stack.cmd'


class NdkStackShortcut(ndk.builds.ScriptShortcutModule):
    name = 'ndk-stack-shortcut'
    path = Path('ndk-stack')
    script = Path('prebuilt/{host}/bin/ndk-stack')
    windows_ext = '.cmd'


class NdkWhichShortcut(ndk.builds.ScriptShortcutModule):
    name = 'ndk-which-shortcut'
    path = Path('ndk-which')
    script = Path('prebuilt/{host}/bin/ndk-which')
    windows_ext = ''  # There isn't really a Windows ndk-which.


class NdkBuildShortcut(ndk.builds.ScriptShortcutModule):
    name = 'ndk-build-shortcut'
    path = Path('ndk-build')
    script = Path('build/ndk-build')
    windows_ext = '.cmd'


class Readme(ndk.builds.FileModule):
    name = 'readme'
    path = Path('README.md')
    src = NDK_DIR / 'UserReadme.md'


CANARY_TEXT = textwrap.dedent("""\
    This is a canary build of the Android NDK. It's updated almost every day.

    Canary builds are designed for early adopters and can be prone to breakage.
    Sometimes they can break completely. To aid development and testing, this
    distribution can be installed side-by-side with your existing, stable NDK
    release.
    """)


class CanaryReadme(ndk.builds.Module):
    name = 'canary-readme'
    path = Path('README.canary')
    no_notice = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        if ndk.config.canary:
            self.get_install_path().write_text(CANARY_TEXT)


class Meta(ndk.builds.PackageModule):
    name = 'meta'
    path = Path('meta')
    src = NDK_DIR / 'meta'
    no_notice = True

    deps = {
        'base-toolchain',
    }

    def install(self) -> None:
        super().install()
        self.create_system_libs_meta()

    def create_system_libs_meta(self) -> None:
        # Build system_libs.json based on what we find in the toolchain. We
        # only need to scan a single 32-bit architecture since these libraries
        # do not vary in availability across architectures.
        sysroot_base = (self.get_dep('base-toolchain').get_install_path() /
                        'sysroot/usr/lib/arm-linux-androideabi')

        system_libs: Dict[str, str] = {}
        for api_name in sorted(os.listdir(sysroot_base)):
            path = os.path.join(sysroot_base, api_name)

            # There are also non-versioned libraries in this directory.
            if not os.path.isdir(path):
                continue

            for lib in os.listdir(path):
                # Don't include CRT objects in the list.
                if not lib.endswith('.so'):
                    continue

                if not lib.startswith('lib'):
                    raise RuntimeError(
                        'Found unexpected file in sysroot: {}'.format(lib))

                # libc++.so is a linker script, not a system library.
                if lib == 'libc++.so':
                    continue

                # We're processing each version directory in sorted order, so
                # if we've already seen this library before it is an earlier
                # version of the library.
                if lib in system_libs:
                    continue

                system_libs[lib] = api_name

        system_libs = collections.OrderedDict(sorted(system_libs.items()))

        json_path = os.path.join(self.get_install_path(), 'system_libs.json')
        with open(json_path, 'w') as json_file:
            json.dump(system_libs, json_file, indent=2, separators=(',', ': '))


class WrapSh(ndk.builds.PackageModule):
    name = 'wrap.sh'
    path = Path('wrap.sh')
    src = NDK_DIR / 'wrap.sh'
    no_notice = True


class SourceProperties(ndk.builds.Module):
    name = 'source.properties'
    path = Path('source.properties')
    no_notice = True

    def build(self) -> None:
        pass

    def install(self) -> None:
        path = self.get_install_path()
        with open(path, 'w') as source_properties:
            assert self.context is not None
            version = get_version_string(self.context.build_number)
            if ndk.config.beta > 0:
                version += '-beta{}'.format(ndk.config.beta)
            source_properties.writelines([
                'Pkg.Desc = Android NDK\n',
                'Pkg.Revision = {}\n'.format(version)
            ])


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
        with open(notice_path, encoding='utf-8') as notice_file:
            licenses.add(notice_file.read())

    with path.open('w', encoding='utf-8') as output_file:
        # Sorting the contents here to try to make things deterministic.
        output_file.write(os.linesep.join(sorted(list(licenses))))


def launch_build(worker: ndk.workqueue.Worker, module: ndk.builds.Module,
                 log_dir: Path) -> Tuple[bool, ndk.builds.Module]:
    result = do_build(worker, module, log_dir)
    if not result:
        return result, module
    do_install(worker, module)
    return True, module


def do_build(worker: ndk.workqueue.Worker, module: ndk.builds.Module,
             log_dir: Path) -> bool:
    with module.log_path(log_dir).open('w') as log_file:
        # print("XC - log file = ", module.log_path(log_dir))
        os.dup2(log_file.fileno(), sys.stdout.fileno())
        os.dup2(log_file.fileno(), sys.stderr.fileno())
        try:
            worker.status = 'Building {}...'.format(module)
            module.build()
            return True
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            return False


def do_install(worker: ndk.workqueue.Worker,
               module: ndk.builds.Module) -> None:
    worker.status = 'Installing {}...'.format(module)
    module.install()


def _get_transitive_module_deps(
        module: ndk.builds.Module, deps: Set[ndk.builds.Module],
        unknown_deps: Set[str], seen: Set[ndk.builds.Module]) -> None:
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
        module: ndk.builds.Module) -> Tuple[Set[ndk.builds.Module], Set[str]]:
    seen: Set[ndk.builds.Module] = set()
    deps: Set[ndk.builds.Module] = set()
    unknown_deps: Set[str] = set()
    _get_transitive_module_deps(module, deps, unknown_deps, seen)
    return deps, unknown_deps


def get_modules_to_build(
        module_names: Iterable[str]
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
        sys.exit('Unknown modules: {}'.format(
            ', '.join(sorted(list(unknown_modules)))))

    build_modules = []
    for module in modules:
        build_modules.append(module)

    return sorted(list(build_modules), key=str), deps_only


ALL_MODULES = [
    BaseToolchain(),
    CanaryReadme(),
    Changelog(),
    Clang(),
    CpuFeatures(),
    #Gdb(),
    Gtest(),
    LibAndroidSupport(),
    LibShaderc(),
    Libcxx(),
    Libcxxabi(),
    Make(),
    Meta(),
    NativeAppGlue(),
    NdkBuild(),
    NdkBuildShortcut(),
    #NdkGdb(),
    #NdkGdbShortcut(),
    NdkLldbShortcut(),
    NdkHelper(),
    NdkStack(),
    NdkStackShortcut(),
    NdkWhich(),
    NdkWhichShortcut(),
    Platforms(),
    Python(),
    PythonPackages(),
    Readme(),
    RenderscriptLibs(),
    RenderscriptToolchain(),
    #ShaderTools(),
    SimplePerf(),
    SourceProperties(),
    Sysroot(),
    SystemStl(),
    Toolbox(),
    Toolchain(),
    Vulkan(),
    WrapSh(),
    Yasm(),
]


NAMES_TO_MODULES = {m.name: m for m in ALL_MODULES}


def get_all_module_names() -> List[str]:
    return [m.name for m in ALL_MODULES if m.enabled]


def build_number_arg(value: str) -> str:
    if value.startswith('P'):
        # Treehugger build. Treat as a local development build.
        return '0'
    return value


def parse_args() -> Tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(
        description=inspect.getdoc(sys.modules[__name__]))

    parser.add_argument(
        '-j', '--jobs', type=int, default=multiprocessing.cpu_count(),
        help=('Number of parallel builds to run. Note that this will not '
              'affect the -j used for make; this just parallelizes '
              'checkbuild.py. Defaults to the number of CPUs available.'))

    parser.add_argument(
        '--skip-deps', action='store_true',
        help=('Assume that dependencies have been built and only build '
              'explicitly named modules.'))

    package_group = parser.add_mutually_exclusive_group()
    package_group.add_argument(
        '--package', action='store_true', dest='package',
        help='Package the NDK when done building.')
    package_group.add_argument(
        '--no-package', action='store_false', dest='package',
        help='Do not package the NDK when done building (default).')

    test_group = parser.add_mutually_exclusive_group()
    test_group.add_argument(
        '--build-tests', action='store_true', dest='build_tests', default=True,
        help=textwrap.dedent("""\
        Build tests when finished. --package is required. Not supported
        when targeting Windows.
        """))
    test_group.add_argument(
        '--no-build-tests', action='store_false', dest='build_tests',
        help='Skip building tests after building the NDK.')

    parser.add_argument(
        '--build-number', default='0', type=build_number_arg,
        help='Build number for use in version files.')
    parser.add_argument(
        '--release', help='Ignored. Temporarily compatibility.')

    parser.add_argument(
        '--system',
        choices=Host,
        type=Host,
        default=Host.current(),
        help='Build for the given OS.')

    module_group = parser.add_mutually_exclusive_group()

    module_group.add_argument(
        '--module', dest='modules', action='append', default=[],
        choices=get_all_module_names(), help='NDK modules to build.')

    return parser.parse_known_args()


def log_build_failure(log_path: str, dist_dir: str) -> None:
    with open(log_path, 'r') as log_file:
        contents = log_file.read()
        print(contents)

        # The build server has a build_error.log file that is supposed to be
        # the short log of the failure that stopped the build. Append our
        # failing log to that.
        build_error_log = os.path.join(dist_dir, 'logs/build_error.log')
        with open(build_error_log, 'a') as error_log:
            error_log.write('\n')
            error_log.write(contents)


def launch_buildable(deps: ndk.deps.DependencyManager,
                     workqueue: ndk.workqueue.AnyWorkQueue, log_dir: Path,
                     skip_deps: bool,
                     skip_modules: Set[ndk.builds.Module]) -> None:
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
            workqueue.add_task(launch_build, module, log_dir)


def wait_for_build(deps: ndk.deps.DependencyManager,
                   workqueue: ndk.workqueue.AnyWorkQueue, dist_dir: str,
                   log_dir: Path, skip_deps: bool,
                   skip_modules: Set[ndk.builds.Module]) -> None:
    console = ndk.ansi.get_console()
    ui = ndk.ui.get_build_progress_ui(console, workqueue)
    with ndk.ansi.disable_terminal_echo(sys.stdin):
        with console.cursor_hide_context():
            while not workqueue.finished():
                result, module = workqueue.get_result()
                if not result:
                    ui.clear()
                    print('Build failed: {}'.format(module))
                    log_build_failure(
                        module.log_path(log_dir), dist_dir)
                    sys.exit(1)
                elif not console.smart_console:
                    ui.clear()
                    print('Build succeeded: {}'.format(module))

                deps.complete(module)
                launch_buildable(deps, workqueue, log_dir, skip_deps,
                                 skip_modules)

                ui.draw()
            ui.clear()
            print('Build finished')


def check_ndk_symlink(ndk_dir: Path, src: Path, target: Path) -> None:
    """Check that the symlink's target is relative, exists, and points within
    the NDK installation.
    """
    if target.is_absolute():
        raise RuntimeError(f'Symlink {src} points to absolute path {target}')
    ndk_dir = ndk_dir.resolve()
    cur = src.parent.resolve()
    for part in target.parts:
        # (cur / part) might itself be a symlink. Its validity is checked from
        # the top-level scan, so it doesn't need to be checked here.
        cur = (cur / part).resolve()
        if not cur.exists():
            raise RuntimeError(f'Symlink {src} targets non-existent {cur}')
        if not cur.is_relative_to(ndk_dir):
            raise RuntimeError(
                f'Symlink {src} targets {cur} outside NDK {ndk_dir}')


def check_ndk_symlinks(ndk_dir: Path, host: Host) -> None:
    for path in ndk.paths.walk(ndk_dir):
        if not path.is_symlink():
            continue
        if host == Host.Windows64:
            # Symlinks aren't supported well enough on Windows. (e.g. They
            # require Developer Mode and/or special permissions. Cygwin
            # tools might create symlinks that non-Cygwin programs don't
            # recognize.)
            raise RuntimeError(f'Symlink {path} unexpected in Windows NDK')
        # print(" --- path = ", path.readlink())
        # XC-TODO: check it later
        # check_ndk_symlink(ndk_dir, path, path.readlink())


def build_ndk(modules: List[ndk.builds.Module],
              deps_only: Set[ndk.builds.Module], out_dir: Path, dist_dir: Path,
              args: argparse.Namespace) -> Path:
    build_context = ndk.builds.BuildContext(
        out_dir, dist_dir, ALL_MODULES, args.system, args.build_number)

    for module in modules:
        module.context = build_context

    log_dir = dist_dir / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)

    ndk_dir = Path(ndk.paths.get_install_path(str(out_dir), args.system))
    ndk_dir.mkdir(parents=True, exist_ok=True)

    deps = ndk.deps.DependencyManager(modules)
    workqueue = ndk.workqueue.WorkQueue(args.jobs)
    try:
        launch_buildable(deps, workqueue, log_dir, args.skip_deps,
                         deps_only)
        wait_for_build(deps, workqueue, str(dist_dir), log_dir,
                       args.skip_deps, deps_only)

        if deps.get_buildable():
            raise RuntimeError(
                'Builder stopped early. Modules are still '
                'buildable: {}'.format(', '.join(str(deps.get_buildable()))))

        create_notice_file(ndk_dir / 'NOTICE', ndk.builds.NoticeGroup.BASE)
        create_notice_file(ndk_dir / 'NOTICE.toolchain',
                           ndk.builds.NoticeGroup.TOOLCHAIN)
        check_ndk_symlinks(ndk_dir, args.system)
        return ndk_dir
    finally:
        workqueue.terminate()
        workqueue.join()


def build_ndk_for_cross_compile(out_dir: Path,
                                args: argparse.Namespace) -> None:
    args = copy.deepcopy(args)
    args.system = Host.current()
    if args.system != Host.Linux:
        raise NotImplementedError
    module_names = NAMES_TO_MODULES.keys()
    modules, deps_only = get_modules_to_build(module_names)
    print('Building Linux modules: {}'.format(' '.join(
        [str(m) for m in modules])))
    build_ndk(modules, deps_only, out_dir, out_dir, args)


def create_ndk_symlink(out_dir: str) -> None:
    this_host_ndk = ndk.paths.get_install_path()
    ndk_symlink = os.path.join(out_dir, os.path.basename(this_host_ndk))
    if not os.path.exists(ndk_symlink):
        os.symlink(this_host_ndk, ndk_symlink)


def get_directory_size(path: Path) -> int:
    du_str = subprocess.check_output(['du', '-sm', str(path)])
    match = re.match(r'^(\d+)', du_str.decode('utf-8'))
    if match is None:
        raise RuntimeError(f'Could not determine the size of {path}')
    size_str = match.group(1)
    return int(size_str)


def main() -> None:
    logging.basicConfig()

    total_timer = ndk.timer.Timer()
    total_timer.start()

    args, module_names = parse_args()
    module_names.extend(args.modules)
    if not module_names:
        module_names = get_all_module_names()

    required_package_modules = set(get_all_module_names())
    have_required_modules = required_package_modules <= set(module_names)

    # TODO(danalbert): wine?
    # We're building the Windows packages from Linux, so we can't actually run
    # any of the tests from here.
    if args.system.is_windows or not have_required_modules:
        args.build_tests = False

    os.chdir(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    # Set ANDROID_BUILD_TOP.
    if 'ANDROID_BUILD_TOP' in os.environ:
        sys.exit(textwrap.dedent("""\
            Error: ANDROID_BUILD_TOP is already set in your environment.

            This typically means you are running in a shell that has lunched a
            target in a platform build. The platform environment interferes
            with the NDK build environment, so the build cannot continue.

            Launch a new shell before building the NDK."""))

    os.environ['ANDROID_BUILD_TOP'] = ndk.paths.android_path()

    out_dir = ndk.paths.get_out_dir()
    dist_dir = ndk.paths.get_dist_dir(out_dir)

    print('Machine has {} CPUs'.format(multiprocessing.cpu_count()))

    if args.system.is_windows and not args.skip_deps:
        # Since the Windows NDK is cross compiled, we need to build a Linux NDK
        # first so we can build components like libc++.
        build_ndk_for_cross_compile(Path(out_dir), args)

    modules, deps_only = get_modules_to_build(module_names)
    print('Building modules: {}'.format(' '.join(
        [str(m) for m in modules
         if not args.skip_deps or m not in deps_only])))

    build_timer = ndk.timer.Timer()
    with build_timer:
        ndk_dir = build_ndk(modules, deps_only, Path(out_dir), Path(dist_dir),
                            args)
    installed_size = get_directory_size(ndk_dir)

    # Create a symlink to the NDK usable by this host in the root of the out
    # directory for convenience.
    create_ndk_symlink(out_dir)

    package_timer = ndk.timer.Timer()
    with package_timer:
        if args.package:
            print('Packaging NDK...')
            # NB: Purging of unwanted files (.pyc, Android.bp, etc) happens as
            # part of packaging. If testing is ever moved to happen before
            # packaging, ensure that the directory is purged before and after
            # building the tests.
            package_path = package_ndk(ndk_dir, Path(out_dir),
                                       Path(dist_dir), args.system,
                                       args.build_number)
            packaged_size_bytes = os.path.getsize(package_path)
            packaged_size = packaged_size_bytes // (2 ** 20)

    good = True
    test_timer = ndk.timer.Timer()
    with test_timer:
        if args.build_tests:
            good = build_ndk_tests(out_dir, dist_dir, args)
            print()  # Blank line between test results and timing data.

    total_timer.finish()

    print('')
    print('Installed size: {} MiB'.format(installed_size))
    if args.package:
        print('Package size: {} MiB'.format(packaged_size))
    print('Finished {}'.format('successfully' if good else 'unsuccessfully'))
    print('Build: {}'.format(build_timer.duration))
    print('Packaging: {}'.format(package_timer.duration))
    print('Testing: {}'.format(test_timer.duration))
    print('Total: {}'.format(total_timer.duration))

    subject = 'NDK Build {}!'.format('Passed' if good else 'Failed')
    body = 'Build finished in {}'.format(total_timer.duration)
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


if __name__ == '__main__':
    _run_main_in_new_process_group()
