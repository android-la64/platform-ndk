LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := foo
LOCAL_SRC_FILES := foo.cpp
LOCAL_CPPFLAGS := -fno-integrated-as
include $(BUILD_EXECUTABLE)
