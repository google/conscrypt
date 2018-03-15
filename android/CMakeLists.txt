cmake_minimum_required(VERSION 3.4.1)
add_library(conscrypt_jni
            SHARED
            ../common/src/jni/main/cpp/conscrypt/compatibility_close_monitor.cc
            ../common/src/jni/main/cpp/conscrypt/jniload.cc
            ../common/src/jni/main/cpp/conscrypt/jniutil.cc
            ../common/src/jni/main/cpp/conscrypt/native_crypto.cc
            ../common/src/jni/main/cpp/conscrypt/netutil.cc
            ../common/src/jni/main/cpp/conscrypt/trace.cc
            )
include_directories(../common/src/jni/main/include/
                    ../common/src/jni/unbundled/include/
                    ${BORINGSSL_HOME}/include)

find_library(android-log-lib log)
target_link_libraries(conscrypt_jni ${android-log-lib} ssl crypto)

add_definitions(-DANDROID
                -fvisibility=hidden
                -DBORINGSSL_SHARED_LIBRARY
                -DBORINGSSL_IMPLEMENTATION
                -DOPENSSL_SMALL
                -D_XOPEN_SOURCE=700
                -Wno-unused-parameter
                # The following two lines are taken from BoringSSL's build file.  As written there:
                #
                # Clang's -Wtautological-constant-compare is far too aggressive and does not
                # account for, say, wanting the same code to work on both 32-bit and 64-bit
                # platforms.
                #
                # TODO: Remove these when the NDK no longer includes a version that has
                # -Wtautological-constant-compare enabled as part of -Wall
                -Wno-tautological-constant-compare
                -Wtautological-constant-out-of-range-compare)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=armv8-a+crypto")
endif()

add_subdirectory(${BORINGSSL_HOME} ${CMAKE_CURRENT_BINARY_DIR}/boringssl)
