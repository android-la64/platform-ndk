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
"""Tests for ndk.ext.subprocess."""
from __future__ import absolute_import

import textwrap
import traceback
from subprocess import CalledProcessError

import pytest

import ndk.ext.subprocess


class TestVerboseSubprocessErrors:
    def test_capture_both(self) -> None:
        with pytest.raises(CalledProcessError) as excinfo:
            with ndk.ext.subprocess.verbose_subprocess_errors():
                raise CalledProcessError(1, ["test"], "foo", "bar")
        assert (
            textwrap.dedent(
                """\
                ndk.ext.subprocess.VerboseCalledProcessError: Command '['test']' returned non-zero exit status 1.
                stdout:
                foo
                stderr:
                bar
                """
            )
            == "".join(traceback.format_exception_only(excinfo.value))
        )

    def test_capture_stdout(self) -> None:
        with pytest.raises(CalledProcessError) as excinfo:
            with ndk.ext.subprocess.verbose_subprocess_errors():
                raise CalledProcessError(1, ["test"], "foo", None)
        assert (
            textwrap.dedent(
                """\
                ndk.ext.subprocess.VerboseCalledProcessError: Command '['test']' returned non-zero exit status 1.
                stdout:
                foo
                """
            )
            == "".join(traceback.format_exception_only(excinfo.value))
        )

    def test_capture_stderr(self) -> None:
        with pytest.raises(CalledProcessError) as excinfo:
            with ndk.ext.subprocess.verbose_subprocess_errors():
                raise CalledProcessError(1, ["test"], None, "bar")
        assert (
            textwrap.dedent(
                """\
                ndk.ext.subprocess.VerboseCalledProcessError: Command '['test']' returned non-zero exit status 1.
                stderr:
                bar
                """
            )
            == "".join(traceback.format_exception_only(excinfo.value))
        )

    def test_capture_neither(self) -> None:
        with pytest.raises(CalledProcessError) as excinfo:
            with ndk.ext.subprocess.verbose_subprocess_errors():
                raise CalledProcessError(1, ["test"], None, None)
        assert (
            textwrap.dedent(
                """\
                ndk.ext.subprocess.VerboseCalledProcessError: Command '['test']' returned non-zero exit status 1.
                """
            )
            == "".join(traceback.format_exception_only(excinfo.value))
        )
