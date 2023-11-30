from ndk.test.devices import DeviceConfig
from ndk.test.devicetest.case import TestCase


def build_unsupported(test: TestCase) -> str | None:
    if test.config.abi != "arm64-v8a":
        return f"{test.config.abi}"
    return None


def run_unsupported(test: TestCase, device: DeviceConfig) -> str | None:
    if device.version < 34:
        return f"{device.version}"
    if not device.supports_mte:
        return "MTE not enabled"
    return None


def run_broken(test: TestCase, device: DeviceConfig) -> tuple[str | None, str | None]:
    return None, None


def extra_cmake_flags() -> list[str]:
    return ["-DANDROID_SANITIZE=memtag"]
