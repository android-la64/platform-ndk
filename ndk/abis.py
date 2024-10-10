#
# Copyright (C) 2017 The Android Open Source Project
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
"""Constants and helper functions for NDK ABIs."""
from collections.abc import Iterator
from typing import NewType, Optional

from .platforms import (
    FIRST_LOONGARCH64_API_LEVEL,
    FIRST_LP64_API_LEVEL,
    FIRST_RISCV64_API_LEVEL,
    MIN_API_LEVEL,
)

Arch = NewType("Arch", str)
Abi = NewType("Abi", str)
Toolchain = NewType("Toolchain", str)


LP32_ABIS = (
    Abi("armeabi-v7a"),
    Abi("x86"),
)


LP64_ABIS = (
    Abi("arm64-v8a"),
    Abi("loongarch64"),
    Abi("riscv64"),
    Abi("x86_64"),
)


ALL_ABIS = sorted(LP32_ABIS + LP64_ABIS)


ALL_ARCHITECTURES = (
    Arch("arm"),
    Arch("arm64"),
    Arch("loongarch64"),
    Arch("riscv64"),
    Arch("x86"),
    Arch("x86_64"),
)


ALL_TRIPLES = (
    "arm-linux-androideabi",
    "aarch64-linux-android",
    "loongarch64-linux-android",
    "riscv64-linux-android",
    "i686-linux-android",
    "x86_64-linux-android",
)


def arch_to_triple(arch: Arch) -> str:
    """Returns the triple for the given architecture."""
    return dict(zip(ALL_ARCHITECTURES, ALL_TRIPLES))[arch]


def abi_to_arch(abi: Abi) -> Arch:
    """Returns the architecture for the given ABI."""
    return {
        Abi("armeabi-v7a"): Arch("arm"),
        Abi("arm64-v8a"): Arch("arm64"),
        Abi("loongarch64"): Arch("loongarch64"),
        Abi("riscv64"): Arch("riscv64"),
        Abi("x86"): Arch("x86"),
        Abi("x86_64"): Arch("x86_64"),
    }[abi]


def abi_to_triple(abi: Abi) -> str:
    """Returns the triple for the given ABI."""
    return arch_to_triple(abi_to_arch(abi))


def clang_target(abi: Abi, api: Optional[int] = None) -> str:
    """Returns the Clang target to be used for the given ABI/API combo.

    api: API level to compile for. Defaults to the lowest supported API
        level for the architecture if None.
    """
    if api is None:
        api = min_api_for_abi(abi)
    triple = abi_to_triple(abi)
    if abi == Abi("armeabi-v7a"):
        triple = "armv7a-linux-androideabi"
    return f"{triple}{api}"


def min_api_for_abi(abi: Abi) -> int:
    """Returns the minimum supported build API for the given ABI.

    >>> min_api_for_abi(Abi('arm64-v8a'))
    21

    >>> min_api_for_abi(Abi('armeabi-v7a'))
    21

    >>> min_api_for_abi(Abi('foobar'))
    Traceback (most recent call last):
        ...
    ValueError: Invalid ABI: foobar
    """
    if abi == Abi("loongarch64"):
        return FIRST_LOONGARCH64_API_LEVEL
    if abi == Abi("riscv64"):
        return FIRST_RISCV64_API_LEVEL
    if abi in LP64_ABIS:
        return FIRST_LP64_API_LEVEL
    if abi in LP32_ABIS:
        return MIN_API_LEVEL
    raise ValueError("Invalid ABI: {}".format(abi))


def iter_abis_for_api(api: int) -> Iterator[Abi]:
    """Returns an Iterator over ABIs available at the given API level."""
    for abi in ALL_ABIS:
        if min_api_for_abi(abi) <= api:
            yield abi
