cmake_minimum_required(VERSION 3.6)
project(CMakeDefaultFlagsTest CXX)

set(GTEST_PATH "${ANDROID_NDK}/sources/third_party/googletest")

add_library(mte-smoke-cmake SHARED
    ${GTEST_PATH}/src/gtest-all.cc
    jni/mte_oob_test.cc)

add_executable(mte-smoke-cmake_exe
    jni/mte_oob_test.cc
    ${GTEST_PATH}/src/gtest-all.cc
    ${GTEST_PATH}/src/gtest_main.cc
)

target_include_directories(mte-smoke-cmake PRIVATE ${GTEST_PATH}/include ${GTEST_PATH})
target_include_directories(mte-smoke-cmake_exe PRIVATE ${GTEST_PATH}/include ${GTEST_PATH})
