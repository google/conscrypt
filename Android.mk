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

#
# Build for the target (device).
#

bundled_test_java_files := $(call all-java-files-under,platform/src/test/java)
bundled_test_java_files += $(filter-out %/ConscryptSuite.java,\
    $(call all-java-files-under,openjdk-integ-tests/src/test/java))
bundled_test_java_files += $(call all-java-files-under,testing/src/main/java)
bundled_test_java_files := $(foreach j,$(bundled_test_java_files),\
	$(if $(findstring testing/src/main/java/libcore/,$(j)),,$(j)))

ifeq ($(LIBCORE_SKIP_TESTS),)
# Make the conscrypt-tests library.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(bundled_test_java_files)
LOCAL_JAVA_RESOURCE_DIRS := openjdk/src/test/resources openjdk-integ-tests/src/test/resources
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := \
    core-oj \
    core-libart \
    junit \
    mockito-target-minus-junit4
LOCAL_STATIC_JAVA_LIBRARIES := \
    core-tests-support \
    conscrypt-nojarjar \
    bouncycastle-unbundled \
    bouncycastle-bcpkix-unbundled \
    bouncycastle-ocsp-unbundled
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-tests
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)

bundled_benchmark_java_files := $(call all-java-files-under,testing/src/main/java)
bundled_benchmark_java_files := $(foreach j,$(bundled_benchmark_java_files),\
	$(if $(findstring testing/src/main/java/libcore/,$(j)),,$(j)))
bundled_benchmark_java_files += $(call all-java-files-under,benchmark-base/src/main/java)
bundled_benchmark_java_files += $(call all-java-files-under,benchmark-android/src/main/java)

# Make the conscrypt-benchmarks library.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(bundled_benchmark_java_files)
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := \
    core-oj \
    core-libart \
    junit \
    bouncycastle-unbundled \
    bouncycastle-bcpkix-unbundled \
    bouncycastle-ocsp-unbundled \
    caliper-api-target
LOCAL_STATIC_JAVA_LIBRARIES := core-tests-support conscrypt-nojarjar
LOCAL_JAVACFLAGS := $(local_javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := conscrypt-benchmarks
LOCAL_REQUIRED_MODULES := libjavacrypto
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
LOCAL_JAVA_LANGUAGE_VERSION := 1.7
include $(BUILD_STATIC_JAVA_LIBRARY)
endif

#
# Build for the host.
#

ifeq ($(HOST_OS),linux)

# Make the conscrypt-tests library.
ifeq ($(LIBCORE_SKIP_TESTS),)
    include $(CLEAR_VARS)
    LOCAL_SRC_FILES := $(bundled_test_java_files)
    LOCAL_JAVA_RESOURCE_DIRS := openjdk/src/test/resources openjdk-integ-tests/src/test/resources
    LOCAL_JAVA_LIBRARIES := \
        bouncycastle-unbundled-hostdex \
        bouncycastle-bcpkix-unbundled-hostdex \
        bouncycastle-ocsp-unbundled-hostdex \
        junit-hostdex \
        core-tests-support-hostdex \
        mockito-api-hostdex
    LOCAL_STATIC_JAVA_LIBRARIES := conscrypt-nojarjar-hostdex
    LOCAL_JAVACFLAGS := $(local_javac_flags)
    LOCAL_MODULE_TAGS := optional
    LOCAL_MODULE := conscrypt-tests-hostdex
    LOCAL_REQUIRED_MODULES := libjavacrypto
    LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
    LOCAL_JAVA_LANGUAGE_VERSION := 1.7
    include $(BUILD_HOST_DALVIK_JAVA_LIBRARY)
endif

endif # HOST_OS == linux

# clear out local variables
local_javac_flags :=
bundled_test_java_files :=
