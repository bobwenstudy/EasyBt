# define source directory
SRC		+= $(PORT_PATH)

# define include directory
INCLUDE	+= $(PORT_PATH)

# define lib directory
LIB		+=

LIB_DIR = ../Libraries

CMSIS_DIR = $(LIB_DIR)/CMSIS
CMSIS_DEVICE_DIR = $(CMSIS_DIR)/Device/ARM/ARMCM0

PLATFORM_ROOT_PATH := $(ROOT_PATH)/platform
INCLUDE	+= $(PLATFORM_ROOT_PATH)

PLATFORM_PATH := $(PLATFORM_ROOT_PATH)/cm0
include $(PLATFORM_PATH)/build.mk
