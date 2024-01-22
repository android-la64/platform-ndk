// Make sure we're not clobbering libc++ headers with libandroid_support.
#include <cmath>

// Use iostream instead of stdio.h to make sure we can actually get symbols from
// libc++.so. Most of libc++ is defined in the headers, but std::cout is in the
// library.
#include <iostream>

// If std::strings don't work then there's really no point :)
#include <string>

void foo(const std::string& s) {
  // Using new makes sure we get libc++abi/libsupc++. Using std::string makes
  // sure the STL works at all. Using std::cout makes sure we can access the
  // library itself and not just the headers.
  std::string* copy = new std::string(s);
  std::cout << copy << std::endl;
  delete copy;
}

int main(int, char**) {
  foo("Hello, world!");
}
