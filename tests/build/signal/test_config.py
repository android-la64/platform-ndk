def build_unsupported(test):
    if test.config.abi in ('arm64-v8a', 'x86_64', 'loongarch64'):
        return test.config.abi
    return None
