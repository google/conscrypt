# -*- mode: makefile -*-
# Copyright (C) 2013 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Definitions for building the Conscrypt Java library, native code,
# and associated tests.
#

#
# Common definitions for host and target.
#

# Conscrypt is divided into modules.
#
# The structure is:
#
#   constants/
#       src/gen             # Generates NativeConstants.java.
#   common/
#       src/main/java       # Common Java source for all platforms.
#       src/jni/
#            main           # Common C++ source for all platforms.
#            unbundled      # C++ source used for OpenJDK and unbundled Android.
#   android/
#       src/main/java       # Java source for unbundled Android.
#   openjdk/
#       src/main/java       # Java source for OpenJDK.
#       src/test
#            java/          # Java source for common tests.
#            resources/     # Support files for tests
#   platform/
#       src/main/java       # Java source for bundled Android.
#       src/test
#            java/          # Java source for bundled tests.
#
# All subdirectories are optional (hence the "2> /dev/null"s below).

LOCAL_PATH := $(call my-dir)

local_javac_flags:=-Xmaxwarns 9999999
#local_javac_flags+=-Xlint:all -Xlint:-serial,-deprecation,-unchecked

core_cflags := -Wall -Wextra -Werror -Wunused -fvisibility=hidden
core_cppflags := -Wall -Wextra -Werror -Wunused -fvisibility=hidden

#
# Build for the target (device).
#

include $(CLEAR_VARS)
LOCAL_SRC_FILES := constants/src/gen/cpp/generate_constants.cpp
LOCAL_MODULE := conscrypt_generate_constants
LOCAL_SHARED_LIBRARIES := libcrypto libssl
include $(BUILD_HOST_EXECUTABLE)

conscrypt_generate_constants_exe := $(LOCAL_INSTALLED_MODULE)
conscrypt_gen_java_files := $(TARGET_OUT_COMMON_GEN)/conscrypt/org/conscrypt/NativeConstants.java

$(conscrypt_gen_java_files): $(conscrypt_generate_constants_exe)
	mkdir -p $(dir $@)
	$< > $@

common_java_files := $(filter-out \
	%/org/conscrypt/Platform.java \
	%/org/conscrypt/NativeCryptoJni.java \
	, $(call all-java-files-under,common/src/main/java))

# Create the conscrypt library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,platform/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_JAVA_LIBRARY)

# A guaranteed unstripped version of conscrypt.
# The build system may or may not strip the conscrypt jar, but this one will
# not be stripped. See b/24535627.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,platform/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-testdex
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_JAVA_LIBRARY)

# Create the conscrypt library without jarjar for tests
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,platform/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-nojarjar
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)

bundled_test_java_files := $(filter-out \
	%/org/conscrypt/NativeCryptoTest.java \
	%/org/conscrypt/OpenSSLSocketImplTest.java \
	, $(call all-java-files-under,openjdk/src/test/java))
bundled_test_java_files += $(call all-java-files-under,platform/src/test/java)
bundled_test_java_files += $(call all-java-files-under,testing/src/main/java)
bundled_test_java_files := $(foreach j,$(bundled_test_java_files),\
	$(if $(findstring testing/src/main/java/libcore/,$(j)),,$(j)))

ifeq ($(LIBCORE_SKIP_TESTS),)
# Make the conscrypt-tests library.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(bundled_test_java_files)
LOCAL_JAVA_RESOURCE_DIRS := openjdk/src/test/resources
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core-oj core-libart junit bouncycastle mockito-target-minus-junit4
LOCAL_STATIC_JAVA_LIBRARIES := core-tests-support conscrypt-nojarjar
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-tests
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)
endif

# Platform conscrypt crypto JNI library
include $(CLEAR_VARS)
LOCAL_CFLAGS += $(core_cflags)
LOCAL_CFLAGS += -DJNI_JARJAR_PREFIX="com/android/"
LOCAL_CPPFLAGS += $(core_cppflags)
LOCAL_SRC_FILES := $(call all-cpp-files-under,common/src/jni/main/cpp)
LOCAL_C_INCLUDES += \
        external/openssl/include \
        external/openssl \
        libcore/include \
        libcore/luni/src/main/native \
        $(LOCAL_PATH)/common/src/jni/main/include
LOCAL_SHARED_LIBRARIES := libcrypto libjavacore liblog libnativehelper libssl
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libjavacrypto
include $(BUILD_SHARED_LIBRARY)

# Unbundled Conscrypt jar
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,android/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_SDK_VERSION := current
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt_unbundled
LOCAL_JAVA_LIBRARIES := conscrypt-stubs
LOCAL_JACK_FLAGS := -D jack.classpath.default-libraries=false
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)

# Stub library for unbundled builds
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(call all-java-files-under,android-stub/src/main/java)
LOCAL_SDK_VERSION := current
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE := conscrypt-stubs
LOCAL_JACK_FLAGS := -D jack.classpath.default-libraries=false
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)

# Static unbundled Conscrypt crypto JNI library
include $(CLEAR_VARS)
LOCAL_CFLAGS += $(core_cflags)
LOCAL_CPPFLAGS += $(core_cppflags) \
        -DJNI_JARJAR_PREFIX="com/google/android/gms/" \
        -DCONSCRYPT_UNBUNDLED \
        -DSTATIC_LIB
LOCAL_SRC_FILES := $(call all-cpp-files-under,common/src/jni/main/cpp)
LOCAL_C_INCLUDES += \
        external/openssl/include \
        external/openssl \
        $(LOCAL_PATH)/common/src/jni/main/include \
        $(LOCAL_PATH)/common/src/jni/unbundled/include
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libconscrypt_static
LOCAL_STATIC_LIBRARIES := libssl libcrypto
LOCAL_SDK_VERSION := 9
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
LOCAL_NDK_STL_VARIANT := c++_shared
include $(BUILD_STATIC_LIBRARY)

#
# Build for the host.
#

ifeq ($(HOST_OS),linux)

# Make the conscrypt-hostdex library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,platform/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-hostdex
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_HOST_DALVIK_JAVA_LIBRARY)

# Make the conscrypt-hostdex-nojarjar for tests
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,platform/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_BUILD_HOST_DEX := true
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-hostdex-nojarjar
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_HOST_DALVIK_STATIC_JAVA_LIBRARY)

# Make the conscrypt-tests library.
ifeq ($(LIBCORE_SKIP_TESTS),)
    include $(CLEAR_VARS)
    LOCAL_SRC_FILES := $(bundled_test_java_files)
    LOCAL_JAVA_RESOURCE_DIRS := openjdk/src/test/resources
    LOCAL_JAVA_LIBRARIES := bouncycastle-hostdex junit-hostdex core-tests-support-hostdex mockito-api-hostdex
    LOCAL_STATIC_JAVA_LIBRARIES := conscrypt-hostdex-nojarjar
    LOCAL_JAVACFLAGS := $(local_javac_flags)
    LOCAL_MODULE_TAGS := optional
    LOCAL_MODULE := conscrypt-tests-hostdex
    LOCAL_REQUIRED_MODULES := libjavacrypto
    LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
    LOCAL_JAVA_LANGUAGE_VERSION := 1.7
    include $(BUILD_HOST_DALVIK_JAVA_LIBRARY)
endif

# Conscrypt native library for host
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(call all-cpp-files-under,common/src/jni/main/cpp)
LOCAL_C_INCLUDES += \
        external/openssl/include \
        external/openssl \
        libcore/include \
        libcore/luni/src/main/native \
        $(LOCAL_PATH)/common/src/jni/main/include
LOCAL_CPPFLAGS += $(core_cppflags)
LOCAL_LDLIBS += -lpthread
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libjavacrypto
LOCAL_CFLAGS += -DJNI_JARJAR_PREFIX="com/android/"
LOCAL_SHARED_LIBRARIES := libcrypto libjavacore liblog libnativehelper libssl
LOCAL_MULTILIB := both
include $(BUILD_HOST_SHARED_LIBRARY)

endif # HOST_OS == linux

# Conscrypt Java library for host OpenJDK
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_java_files)
LOCAL_SRC_FILES += $(call all-java-files-under,openjdk/src/main/java)
LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
LOCAL_JAVACFLAGS := $(local_javac_flags) -XDignore.symbol.file
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-host
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_HOST_JAVA_LIBRARY)

# clear out local variables
common_java_files :=
conscrypt_gen_java_files :=
conscrypt_generate_constants_exe :=
core_cflags :=
core_cppflags :=
local_javac_flags :=
bundled_test_java_files :=
