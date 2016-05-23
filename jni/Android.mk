LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CFLAGS+= -Wall -Wno-unused-but-set-variable
LOCAL_C_INCLUDES:=
LOCAL_SRC_FILES:= adbtelnd.c
LOCAL_MODULE:= adbtelnd
include $(BUILD_EXECUTABLE)
all:

$(info $(shell (adb shell sh /data/local/tmp/xbin/servedown.sh)))
$(info $(shell (sleep 3)))
$(info $(shell (adb shell "( mkdir /data/local/tmp/xbin >/dev/null 2>&1 )")))
$(info $(shell (adb shell "( mkdir /data/local/tmp/etc >/dev/null 2>&1 )")))
$(info $(shell (adb shell "( mkdir /data/local/tmp/lib >/dev/null 2>&1 )")))
$(info $(shell (adb push ../obj/local/armeabi-v7a/adbtelnd /data/local/tmp/xbin)))
$(info $(shell (adb shell sh -x /data/local/tmp/xbin/serveup.sh)))
