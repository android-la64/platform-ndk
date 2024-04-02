from optparse import Option
from typing import Optional

from ndk.test.devices import Device
from ndk.test.devicetest.case import TestCase


def run_unsupported(test: TestCase, device: Device) -> Optional[str]:
    if device.version < 19:
        return f"{device.version}"
    if device.version >= 28 and test.config.abi == "x86_64":
        # ASAN is flaky with 28 x86_64. It still works with 32-bit or with
        # older platforms.
        return "ASAN is flaky on 28 x86_64 (http://b/37130178)"
    if test.config.abi == "riscv64":
        return "ASAN is unsupported on riscv64"
    return None


def run_broken(test: TestCase, device: Device) -> tuple[Optional[str], Optional[str]]:
    if device.version == 21:
        return f"{device.version}", "https://github.com/android/ndk/issues/1753"
    return None, None
