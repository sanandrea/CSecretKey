LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := hmacenc

LOCAL_SRC_FILES := hmac_sha256.c sha2.c

LOCAL_LDLIBS    += -llog

LOCAL_CFLAGS    := -DANDROID_BUILD

include $(BUILD_SHARED_LIBRARY)