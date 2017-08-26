cmake_minimum_required(VERSION 3.8)

project(vmrun)

set(CMAKE_C_STANDARD 11)

# Make Targets
add_definitions(-std=c11)
add_custom_target(dune COMMAND $(MAKE) -C ${vmrun_SOURCE_DIR} PWD=${vmrun_SOURCE_DIR})

#
# VMRun Kernel Module
#

file(GLOB MOD_SOURCE_FILES "*.c" "*.h")
add_library(dummy_mod ${MOD_SOURCE_FILES})

#set(LINUX_HEADERS_VERSION 4.4.0-83)
#set(LINUX_HEADERS_PATH /usr/src/linux-headers-${LINUX_HEADERS_VERSION})
set(LINUX_DEV_PATH /home/Storage/SSD/Development/Software/eliaskousk/linux)
set(LINUX_PATH ${LINUX_DEV_PATH})
set(LINUX_HEADERS
        ${LINUX_PATH}/arch/x86/include
        ${LINUX_PATH}/arch/x86/include/generated
        ${LINUX_PATH}/arch/x86/include/generated/uapi
        ${LINUX_PATH}/arch/x86/include/uapi
        ${LINUX_PATH}/include
        ${LINUX_PATH}/include/generated
        ${LINUX_PATH}/include/generated/uapi
        ${LINUX_PATH}/include/uapi)
TARGET_INCLUDE_DIRECTORIES(dummy_mod PUBLIC ${LINUX_HEADERS})
TARGET_INCLUDE_DIRECTORIES(dummy_mod PUBLIC kern kern/kvm)

TARGET_COMPILE_DEFINITIONS(dummy_mod PUBLIC __KERNEL__)
TARGET_COMPILE_DEFINITIONS(dummy_mod PUBLIC MODULE)
TARGET_COMPILE_DEFINITIONS(dummy_mod PUBLIC CONFIG_X86_64)

TARGET_COMPILE_OPTIONS(dummy_mod PUBLIC -nostdinc)
TARGET_COMPILE_OPTIONS(dummy_mod PUBLIC -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include)
TARGET_COMPILE_OPTIONS(dummy_mod PUBLIC -include ${LINUX_PATH}/include/linux/kconfig.h)
