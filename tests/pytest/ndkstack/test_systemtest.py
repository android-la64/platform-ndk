#!/usr/bin/env python3
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
"""System tests for ndk-stack.py"""

import os.path
import subprocess
import unittest

import pytest

import ndk.ext.subprocess
import ndk.paths
import ndk.toolchains
from ndk.hosts import Host


class SystemTests(unittest.TestCase):
    """Complete system test of ndk-stack.py script."""

    def system_test(self, backtrace_file: str, expected_file: str) -> None:
        ndk_path = ndk.paths.get_install_path()
        self.assertTrue(
            ndk_path.exists(),
            f"{ndk_path} does not exist. Build the NDK before running this test.",
        )

        ndk_stack = ndk_path / "ndk-stack"
        if Host.current() is Host.Windows64:
            ndk_stack = ndk_stack.with_suffix(".bat")

        symbol_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "files")
        proc = subprocess.run(
            [
                ndk_stack,
                "-s",
                symbol_dir,
                "-i",
                os.path.join(symbol_dir, backtrace_file),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        # Read the expected output.
        file_name = os.path.join(symbol_dir, expected_file)
        with open(file_name, "r", encoding="utf-8") as exp_file:
            expected = exp_file.read()
        expected = expected.replace("SYMBOL_DIR", symbol_dir)
        self.maxDiff = None
        self.assertEqual(expected, proc.stdout)

    def test_all_stacks(self) -> None:
        self.system_test("backtrace.txt", "expected.txt")

    def test_multiple_crashes(self) -> None:
        self.system_test("multiple.txt", "expected_multiple.txt")

    def test_hwasan(self) -> None:
        self.system_test("hwasan.txt", "expected_hwasan.txt")

    @pytest.mark.xfail
    def test_invalid_unicode(self) -> None:
        with ndk.ext.subprocess.verbose_subprocess_errors():
            self.system_test(
                "invalid_unicode_log.txt", "expected_invalid_unicode_log.txt"
            )


if __name__ == "__main__":
    unittest.main()
