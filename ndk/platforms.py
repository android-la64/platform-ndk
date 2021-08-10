#
# Copyright (C) 2021 The Android Open Source Project
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
"""Wrapper around meta/platforms.json."""
import json

from .paths import NDK_DIR


def _load_data() -> tuple[int, int]:
    """Loads and returns the min and max supported versions."""
    with (NDK_DIR / "meta/platforms.json").open() as platforms:
        data = json.load(platforms)
    return data["min"], data["max"]


MIN_API_LEVEL, MAX_API_LEVEL = _load_data()
FIRST_LP64_API_LEVEL = 21
