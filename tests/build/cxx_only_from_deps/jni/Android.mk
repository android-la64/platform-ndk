LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libfoo
LOCAL_SRC_FILES := foo.cpp
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libbar
LOCAL_SRC_FILES := bar.c
LOCAL_STATIC_LIBRARIES := libfoo
include $(BUILD_SHARED_LIBRARY)
