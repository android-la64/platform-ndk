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
"""Tools for verifying and fixing our Python environment."""
import shutil
import site
import sys
import textwrap
from pathlib import Path

from .hosts import Host
from .paths import ANDROID_DIR

PYTHON_DOCS = "https://android.googlesource.com/platform/ndk/+/master/docs/Building.md#python-environment-setup"


def python_path() -> Path:
    """Returns the absolute path to the Python executable for this OS."""
    if Host.current() is Host.Linux:
        return ANDROID_DIR / "prebuilts/python/linux-x86/bin/python3.10"
    if Host.current() is Host.Darwin:
        return ANDROID_DIR / "prebuilts/python/darwin-x86/bin/python3.10"
    return ANDROID_DIR / "prebuilts/python/windows-x86/python.exe"


def ensure_poetry_if_available() -> None:
    if shutil.which("poetry") is None:
        return
    if "pypoetry" not in sys.executable:
        sys.exit(
            textwrap.fill(
                f"Poetry is installed but {sys.executable} does not appear to be a "
                f"Poetry environment. Follow {PYTHON_DOCS} to set up your Python "
                "environment. If you have already configured your environment, "
                "remember to run `poetry shell` to start a shell with the correct "
                "environment, or prefix NDK commands with `poetry run`.",
                break_long_words=False,
                break_on_hyphens=False,
            )
        )


def purge_user_site_packages() -> None:
    if site.ENABLE_USER_SITE:
        sys.path = [p for p in sys.path if p != site.getusersitepackages()]


def ensure_python_environment() -> None:
    """Verifies that the current Python environment is what we expect."""
    ensure_poetry_if_available()
    purge_user_site_packages()
