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
from typing import List, NewType


Arch = NewType('Arch', str)
Abi = NewType('Abi', str)
Toolchain = NewType('Toolchain', str)


LP32_ABIS = (
    Abi('armeabi-v7a'),
    Abi('x86'),
)


LP64_ABIS = (
    Abi('arm64-v8a'),
    Abi('x86_64'),
    Abi('loongarch64'),
)


ALL_ABIS = sorted(LP32_ABIS + LP64_ABIS)


ALL_ARCHITECTURES = (
    Arch('arm'),
    Arch('arm64'),
    Arch('x86'),
    Arch('x86_64'),
    Arch('loongarch64'),
)


ALL_TOOLCHAINS = (
    Toolchain('arm-linux-androideabi'),
    Toolchain('aarch64-linux-android'),
    Toolchain('x86'),
    Toolchain('x86_64'),
    Toolchain('loongarch64-linux-android'),
)


ALL_TRIPLES = (
    'arm-linux-androideabi',
    'aarch64-linux-android',
    'i686-linux-android',
    'x86_64-linux-android',
    'loongarch64-linux-android',
)


def arch_to_toolchain(arch: Arch) -> Toolchain:
    """Returns the NDK toolchain name for the given architecture."""
    return dict(zip(ALL_ARCHITECTURES, ALL_TOOLCHAINS))[arch]


def arch_to_triple(arch: Arch) -> str:
    """Returns the triple for the given architecture."""
    return dict(zip(ALL_ARCHITECTURES, ALL_TRIPLES))[arch]


def toolchain_to_arch(toolchain: Toolchain) -> Arch:
    """Returns the architecture for the given toolchain."""
    return dict(zip(ALL_TOOLCHAINS, ALL_ARCHITECTURES))[toolchain]


def arch_to_abis(arch: Arch) -> List[Abi]:
    """Returns the ABIs for the given architecture."""
    return {
        Arch('arm'): [Abi('armeabi-v7a')],
        Arch('arm64'): [Abi('arm64-v8a')],
        Arch('x86'): [Abi('x86')],
        Arch('x86_64'): [Abi('x86_64')],
        Arch('loongarch64'): [Abi('loongarch64')],
    }[arch]


def abi_to_arch(abi: Abi) -> Arch:
    """Returns the architecture for the given ABI."""
    return {
        Abi('armeabi-v7a'): Arch('arm'),
        Abi('arm64-v8a'): Arch('arm64'),
        Abi('x86'): Arch('x86'),
        Abi('x86_64'): Arch('x86_64'),
        Abi('loongarch64'): Arch('loongarch64'),
    }[abi]


def clang_target(arch: Arch, api: int = None) -> str:
    """Returns the Clang target to be used for the given arch/API combo.

    Args:
        arch: Architecture to compile for. 'arm' will target ARMv7.
        api: API level to compile for. Defaults to the lowest supported API
            level for the architecture if None.
    """
    if api is None:
        # Currently there is only one ABI per arch.
        abis = arch_to_abis(arch)
        assert len(abis) == 1
        abi = abis[0]
        api = min_api_for_abi(abi)
    triple = arch_to_triple(arch)
    if arch == 'arm':
        triple = 'armv7a-linux-androideabi'
    return f'{triple}{api}'


def min_api_for_abi(abi: Abi) -> int:
    """Returns the minimum supported build API for the given ABI.

    >>> min_api_for_abi('arm64-v8a')
    21

    >>> min_api_for_abi('armeabi-v7a')
    16

    >>> min_api_for_abi('foobar')
    Traceback (most recent call last):
        ...
    ValueError: Invalid ABI: foobar
    """
    if abi in LP64_ABIS:
        return 21
    elif abi in LP32_ABIS:
        return 16
    else:
        raise ValueError('Invalid ABI: {}'.format(abi))
