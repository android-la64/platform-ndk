#include <stdlib.h>

#include <gtest/gtest.h>

#if !defined(__aarch64__)
#error "MTE is only supported on AArch64."
#endif

#if !__has_feature(memtag_stack)
#error "Want MTE build"
#endif


TEST(Memtag, OOB) {
  // Cannot assert the death message, because it doesn't get printed to stderr.
  EXPECT_DEATH({
      volatile char* x = const_cast<volatile char*>(reinterpret_cast<char*>(malloc(16)));
      x[17] = '2';
      }, "");
}
