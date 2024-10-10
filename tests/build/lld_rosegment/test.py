#
# Copyright (C) 2020 The Android Open Source Project
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
"""Check that -Wl,--no-rosegment is used when required.

https://github.com/android/ndk/issues/1196
"""
from pathlib import Path
from typing import Optional

from ndk.test.spec import BuildConfiguration
from ndk.testing.flag_verifier import FlagVerifier


def run_test(ndk_path: str, config: BuildConfiguration) -> tuple[bool, Optional[str]]:
    """Checks correct --no-rosegment use."""
    # The 'riscv64/loongarch64' ABI has a minimum supported version of 35, so the below
    # tests of API level 29 and 30 are ignored (the CMake files will simply
    # reset the value to the minimum supported version). Verify that the
    # behavior after API level 30 is retained (--no-rosegment does not appear).
    if config.abi in ("riscv64", "loongarch64"):
        verifier = FlagVerifier(Path("project"), Path(ndk_path), config).with_api(35)
        verifier.expect_not_flag("-Wl,--no-rosegment")
        return verifier.verify().make_test_result_tuple()

    verifier = FlagVerifier(Path("project"), Path(ndk_path), config).with_api(29)
    verifier.expect_flag("-Wl,--no-rosegment")
    verifier.expect_not_flag("-Wl,--rosegment")
    result = verifier.verify()
    if result.failed():
        return result.make_test_result_tuple()

    verifier = FlagVerifier(Path("project"), Path(ndk_path), config).with_api(30)
    verifier.expect_not_flag("-Wl,--no-rosegment")
    return verifier.verify().make_test_result_tuple()
