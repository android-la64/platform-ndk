from ndk.test.devices import DeviceConfig
from ndk.test.devicetest.case import TestCase


def build_unsupported(test: TestCase) -> str | None:
    if test.config.abi != "arm64-v8a":
        return f"{test.config.abi}"
    return None


def run_unsupported(test: TestCase, device: DeviceConfig) -> str | None:
    if device.version < 34:
        return f"{device.version}"
    return None


def run_broken(test: TestCase, device: DeviceConfig) -> tuple[str | None, str | None]:
    # FIXME: support c++_shared tests for cmake and re-enable
    # currently the c++ library is not properly pushed so the
    # test fails to link
    if test.build_system == "cmake":
        return f"{test.build_system}", "https://github.com/android/ndk/issues/1942"
    return None, None


def extra_cmake_flags() -> list[str]:
    return ["-DANDROID_SANITIZE=hwaddress", "-DANDROID_STL=c++_shared"]
