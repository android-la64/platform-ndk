def build_unsupported(test):
    if test.config.abi == 'loongarch64' and test.config.api < 29:
        return test.config.abi
    return None
