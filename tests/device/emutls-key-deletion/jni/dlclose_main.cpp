#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <thread>

// Verify that the emutls key is deleted by spawning and joining a thread. If
// the key isn't deleted, Bionic will try to run the per-thread emutls cleanup
// function in the unloaded library and crash. This step is a regression test
// for b/71814577.

int main() {
  std::thread([] {
    void* solib = dlopen("libndktest.so", RTLD_NOW);
    if (!solib) {
      fprintf(stderr, "can't find libndktest.so (%s)\n", dlerror());
      abort();
    }
    void (*test_func)() = (void(*)())dlsym(solib, "test_func");
    if (!test_func) {
      fprintf(stderr, "can't find test_func func (%s)\n", dlerror());
      abort();
    }
    test_func();
  dlclose(solib);
  }).join();
  return 0;
}
