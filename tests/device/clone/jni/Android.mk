LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := clone
LOCAL_SRC_FILES := clone.c
LOCAL_CFLAGS += -Wno-implicit-function-declaration
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := clone-static
LOCAL_SRC_FILES := clone.c
LOCAL_CFLAGS += -Wno-implicit-function-declaration
LOCAL_LDFLAGS += -static
include $(BUILD_EXECUTABLE)
