#
# Copyright (C) 2022 The Android Open Source Project
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
"""Helper functions for reading and writing .zip and .tar.bz2 archives."""
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

import ndk.paths
from ndk.hosts import Host


def make_bztar(base_name: Path, root_dir: Path, base_dir: Path) -> None:
    """Create a compressed tarball.

    Arguments have the same name and meaning as shutil.make_archive.

    Args:
        base_name: Base name of archive to create. ".tar.bz2" will be appended.
        root_dir: Directory that's the root of the archive.
        base_dir: Directory relative to root_dir to archive.
    """
    if not root_dir.is_dir():
        raise RuntimeError(f"Not a directory: {root_dir}")
    if not (root_dir / base_dir).is_dir():
        raise RuntimeError(f"Not a directory: {root_dir}/{base_dir}")

    if os.name == "nt":
        shutil.make_archive(
            str(base_name),
            "bztar",
            str(root_dir),
            str(base_dir),
        )
    else:
        subprocess.check_call(
            [
                "tar",
                (
                    "-j"
                    if shutil.which("pbzip2") is None
                    else "--use-compress-prog=pbzip2"
                ),
                "-cf",
                str(base_name.with_suffix(".tar.bz2")),
                "-C",
                str(root_dir),
                str(base_dir),
            ]
        )


def make_brtar(
    base_name: Path, root_dir: Path, base_dir: Path, preserve_symlinks: bool
) -> Path:
    """Create a Brotli-compressed tarball.

    Arguments have the same name and meaning as shutil.make_archive.

    Args:
        base_name: Base name of archive to create. ".tar.br" will be appended.
        root_dir: Directory that's the root of the archive.
        base_dir: Directory relative to root_dir to archive.
    """
    if not root_dir.is_dir():
        raise RuntimeError(f"Not a directory: {root_dir}")
    if not (root_dir / base_dir).is_dir():
        raise RuntimeError(f"Not a directory: {root_dir}/{base_dir}")

    br_file = base_name.with_suffix(".tar.br")

    if os.name == "nt":
        raise NotImplementedError
    cmd = ["tar"]
    if not preserve_symlinks:
        cmd.append("--dereference")
    cmd.extend(
        [
            "--use-compress-program",
            str(
                ndk.paths.android_path(
                    "prebuilts/build-tools/{host}-x86/bin/brotli".format(
                        host=Host.current().value
                    )
                )
            )
            # Choice of 7 as quality parameter based on the following data:
            #
            # q | size (MB) | compression time relative to -q 0
            # --+-----------+----------------------------------
            # 0 | 622       |  0:00
            # 2 | 514       |  0:10
            # 5 | 447       |  1:14
            # 6 | 435       |  1:48
            # 7 | 401       |  3:24
            # 8 | 393       |  5:35
            # 9 | 388       | 10:37
            + " -q 7",
            "-cf",
            str(br_file),
            "-C",
            str(root_dir),
            str(base_dir),
        ]
    )
    subprocess.check_call(cmd)
    return br_file


# For (un)zipping archives on Unix-like systems, the "zip" and "unzip" commands
# are pretty universally available.
#
# For Windows, the situation is more complicated. After trying and rejecting
# several options, the somewhat surprising best choice is the "tar"
# command, which is available in Windows since 2018:
# https://docs.microsoft.com/en-us/virtualization/community/team-blog/2017/20171219-tar-and-curl-come-to-windows
# Note that this is bsdtar, which has slightly different command-line flags
# than GNU tar.
#
# For the record, here are other options, and why they didn't work:
#
# - Python's built-in shutil.unpack_archive uses the "zipfile" module, which
#   does not restore permissions, including the executable bit, when
#   unzipping. https://bugs.python.org/issue15795
#
# - 7-zip is popular and works on a wide range of Windows versions,
#   but it is not guaranteed to be available, and is, in fact, not
#   available on our Windows build machines.
#
# - Expand-Archive in PowerShell results in modification times in the future
#   for NDK .zip files, possibly due to not handling time zones correctly.
#
# For more information, see https://superuser.com/questions/1314420/how-to-unzip-a-file-using-the-cmd
#
# See also the following changes:
# - 7-zip: https://android-review.googlesource.com/c/platform/ndk/+/1963599
# - PowerShell: https://android-review.googlesource.com/c/platform/ndk/+/1965510
# - Tar: https://android-review.googlesource.com/c/platform/ndk/+/1967235


def make_zip(
    base_name: Path, root_dir: Path, paths: List[str], preserve_symlinks: bool
) -> Path:
    """Creates a zip package for distribution.

    Args:
        base_name: Path (without extension) to the output archive.
        root_dir: Path to the directory from which to perform the packaging
                  (identical to tar's -C).
        paths: Paths to files and directories to package, relative to root_dir.
        preserve_symlinks: Whether to preserve or flatten symlinks. Should be
            false when creating packages for Windows, but otherwise true.
    """
    if not root_dir.is_dir():
        raise RuntimeError(f"Not a directory: {root_dir}")

    cwd = os.getcwd()
    zip_file = base_name.with_suffix(".zip")
    if zip_file.exists():
        zip_file.unlink()

    # See comment above regarding .zip files on Windows.
    if os.name == "nt":
        # Explicit path, to avoid conflict with Cygwin.
        args = ["c:/windows/system32/tar.exe", "-a"]
        if not preserve_symlinks:
            args.append("-L")
        args.extend(["-cf", str(zip_file)])
    else:
        args = ["zip", "-9qr", str(zip_file)]
        if preserve_symlinks:
            args.append("--symlinks")
    args.extend(paths)
    os.chdir(root_dir)
    try:
        subprocess.check_call(args)
        return zip_file
    finally:
        os.chdir(cwd)


def unzip(zip_file: Path, dest_dir: Path) -> None:
    """Unzip zip_file into dest_dir."""
    if not zip_file.is_file() or zip_file.suffix != ".zip":
        raise RuntimeError(f"Not a .zip file: {zip_file}")
    if not dest_dir.is_dir():
        raise RuntimeError(f"Not a directory: {dest_dir}")

    # See comment above regarding .zip files on Windows.
    if os.name == "nt":
        subprocess.check_call(
            [
                # Explicit path, to avoid conflict with Cygwin.
                "c:/windows/system32/tar.exe",
                "xf",
                str(zip_file),
                "-C",
                str(dest_dir),
            ]
        )
    else:
        # Unzip seems to be pretty universally available on posix systems.
        subprocess.check_call(["unzip", "-qq", str(zip_file), "-d", str(dest_dir)])
