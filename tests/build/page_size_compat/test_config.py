def extra_cmake_flags() -> list[str]:
    return ["-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"]
