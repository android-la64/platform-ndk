from ndk.test.devices import Device
from ndk.test.devicetest.case import TestCase


def build_unsupported(test):
    # TODO(https://github.com/google/android-riscv64/issues/104): Add TSAN when it
    # builds for RISCV64.
    if test.config.is_lp32 or test.config.abi == "riscv64" or test.config.abi == "loongarch64":
        return test.config.abi
    return None


def run_unsupported(test: TestCase, device: Device) -> str | None:
    return "runs indefinitely with latest clang"


def run_broken(test, device):
    return "all", "https://github.com/android/ndk/issues/1171"
