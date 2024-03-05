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
"""Tests that binaries are built with the correct max-page-size."""
from pathlib import Path
from subprocess import CalledProcessError
import subprocess
import re
from collections.abc import Iterator

from ndk.hosts import Host
from ndk.test.spec import BuildConfiguration
from ndk.testing.builders import CMakeBuilder, NdkBuildBuilder


PROJECT_PATH = Path("project")


def iter_load_alignments(readelf_output: str) -> Iterator[tuple[int, int]]:
    """Iterates over the offset and alignment of each LOAD section."""
    # Example output:
    #
    #   Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
    #   PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0002a0 0x0002a0 R   0x8
    #   LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x099604 0x099604 R   0x1000
    pattern = re.compile(r"^\s+LOAD\s+(0x[0-9a-fA-F]+).+(0x[0-9a-fA-F]+)$")
    for line in readelf_output.splitlines():
        if "LOAD" not in line:
            continue
        if (match := pattern.search(line)) is not None:
            yield int(match.group(1), base=16), int(match.group(2), base=16)
        else:
            raise ValueError(f"Could not parse LOAD line {line}")


def verify_load_section_alignment(
    path: Path, ndk: Path, expected_alignment: int
) -> tuple[bool, str | None]:
    """Verifies that each LOAD section in the given file has the correct alignment."""
    readelf = (
        ndk / "toolchains/llvm/prebuilt" / Host.current().tag / "bin" / "llvm-readelf"
    )
    readelf = readelf.with_suffix(Host.current().exe_suffix)
    output = subprocess.run(
        [readelf, "-lW", path], check=True, capture_output=True, text=True
    ).stdout
    for offset, alignment in iter_load_alignments(output):
        if alignment != expected_alignment:
            return (
                False,
                f"LOAD section at {offset:x} has incorrect alignment {alignment:x}. "
                f"Expected {expected_alignment:x}",
            )
    return True, None


def verify_load_section_alignment_each_file(
    paths: list[Path], ndk: Path, expected_alignment: int
) -> tuple[bool, str | None]:
    """Verifies that the LOAD section alignment is correct for each given file."""
    for path in paths:
        result, text = verify_load_section_alignment(path, ndk, expected_alignment)
        if not result:
            return result, text
    return True, None


def run_test(ndk_path: str, config: BuildConfiguration) -> tuple[bool, str | None]:
    """Checks that the binary's LOAD sections have the correct alignment."""
    cmake_builder = CMakeBuilder.from_build_config(PROJECT_PATH, Path(ndk_path), config)
    ndk_build_builder = NdkBuildBuilder.from_build_config(
        PROJECT_PATH, Path(ndk_path), config
    )
    try:
        cmake_builder.build()
        ndk_build_builder.build()
    except CalledProcessError as ex:
        return False, f"Build failed:\n{ex.stdout}"
    return verify_load_section_alignment_each_file(
        [cmake_builder.out_dir / "libfoo.so", ndk_build_builder.out_dir / "libfoo.so"],
        Path(ndk_path),
        expected_alignment=4 * 1024,
    )
