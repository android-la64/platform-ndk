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
from ndk.test.spec import BuildConfiguration
import ndk.testing.standalone_toolchain
import ndk.abis


def run_test(ndk_path: str, config: BuildConfiguration) -> tuple[bool, str]:
    min_api_for_abi = ndk.abis.min_api_for_abi(config.abi)
    arch = ndk.abis.abi_to_arch(config.abi)
    success, out = ndk.testing.standalone_toolchain.run_test(
        ndk_path, config, "foo.cpp", ["--api", str(min_api_for_abi - 1)], []
    )
    if success:
        return (
            False,
            f"{min_api_for_abi} is below minimum supported OS version for "
            f"{config.abi}, but was not rejected",
        )
    expected_error = (
        f"{min_api_for_abi - 1} is less than minimum platform for {arch} "
        f"({min_api_for_abi})"
    )
    if expected_error not in out:
        return (
            False,
            f'expected error message ("{expected_error}") not seen in output: {out}',
        )
    return True, out
