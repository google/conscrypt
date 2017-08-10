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
                -Wno-unused-parameter)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=armv8-a+crypto")
endif()

add_subdirectory(${BORINGSSL_HOME} ${CMAKE_CURRENT_BINARY_DIR}/boringssl)
