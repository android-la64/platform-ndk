def build_unsupported(test):
    if test.config.abi in ("arm64-v8a", "loongarch64", "riscv64", "x86_64"):
        return test.config.abi
    return None
