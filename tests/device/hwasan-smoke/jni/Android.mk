LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := hwasan_smoke
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := hwasan_oob_test.cc
LOCAL_CFLAGS := -fsanitize=hwaddress -fno-omit-frame-pointer
LOCAL_LDFLAGS := -fsanitize=hwaddress
LOCAL_STATIC_LIBRARIES := googletest_main
include $(BUILD_EXECUTABLE)

$(call import-module,third_party/googletest)
