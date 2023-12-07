LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mte_smoke
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := mte_oob_test.cc
LOCAL_CFLAGS := -fsanitize=memtag-stack -march=armv8-a+memtag -fno-omit-frame-pointer
LOCAL_LDFLAGS := -fsanitize=memtag-stack,memtag-heap -fsanitize-memtag-mode=sync -march=armv8-a+memtag
LOCAL_STATIC_LIBRARIES := googletest_main
include $(BUILD_EXECUTABLE)

$(call import-module,third_party/googletest)
