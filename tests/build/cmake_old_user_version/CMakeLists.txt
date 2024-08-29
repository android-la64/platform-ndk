# Arbitrarily low and something that wouldn't actually support Android, but a
# lot of existing projects set this once and never update it, and even when a
# new enough version that does support Android is used, the value used here
# dictates which CMake policies (behavior compatibility flags) are enabled by
# default. We set it to something ancient here to ensure that we can at least
# build a trivial project when old policies are used.
cmake_minimum_required(VERSION 2.8)
project(OldCMakeCompat)

add_executable(foo foo.cpp)
