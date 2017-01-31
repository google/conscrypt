/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONSCRYPT_JNIUTIL_H_
#define CONSCRYPT_JNIUTIL_H_

#include <jni.h>
#include <cstdlib>
#include "ScopedLocalRef.h"
#include "compat.h"
#include "macros.h"

namespace conscrypt {

/**
 * Utility methods for working with JNI.
 */
class JniUtil {
private:
    JniUtil() {}
    ~JniUtil() {}

public:
    /**
     * Obtains the current thread's JNIEnv
     */
    static inline JNIEnv* getJNIEnv(JavaVM* gJavaVM) {
        JNIEnv* env;
#ifdef ANDROID
        if (gJavaVM->AttachCurrentThread(&env, nullptr) < 0) {
#else
        if (gJavaVM->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) < 0) {
#endif
            ALOGE("Could not attach JavaVM to find current JNIEnv");
            return nullptr;
        }
        return env;
    }

    static inline jclass getGlobalRefToClass(JNIEnv* env, const char* className) {
        ScopedLocalRef<jclass> localClass(env, env->FindClass(className));
        jclass globalRef = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
        if (globalRef == nullptr) {
            ALOGE("failed to find class %s", className);
            abort();
        }
        return globalRef;
    }

    static inline jmethodID getMethodRef(JNIEnv* env, jclass clazz, const char* name,
                                         const char* sig) {
        jmethodID localMethod = env->GetMethodID(clazz, name, sig);
        if (localMethod == nullptr) {
            ALOGE("could not find method %s", name);
            abort();
        }
        return localMethod;
    }

    static inline jfieldID getFieldRef(JNIEnv* env, jclass clazz, const char* name,
                                       const char* sig) {
        jfieldID localField = env->GetFieldID(clazz, name, sig);
        if (localField == nullptr) {
            ALOGE("could not find field %s", name);
            abort();
        }
        return localField;
    }

    static inline jclass findClass(JNIEnv* env, const char* name) {
        ScopedLocalRef<jclass> localClass(env, env->FindClass(name));
        jclass result = reinterpret_cast<jclass>(env->NewGlobalRef(localClass.get()));
        if (result == nullptr) {
            ALOGE("failed to find class '%s'", name);
            abort();
        }
        return result;
    }

    /**
     * Register one or more native methods with a particular class.
     * "className" looks like "java/lang/String". Aborts on failure.
     */
    static void jniRegisterNativeMethods(JNIEnv* env, const char* className,
                                        const JNINativeMethod* gMethods, int numMethods) {
        ALOGV("Registering %s's %d native methods...", className, numMethods);

        ScopedLocalRef<jclass> c(env, env->FindClass(className));
        if (c.get() == nullptr) {
            char* msg;
            (void)asprintf(&msg, "Native registration unable to find class '%s'; aborting...",
                           className);
            env->FatalError(msg);
        }

        if (env->RegisterNatives(c.get(), gMethods, numMethods) < 0) {
            char* msg;
            (void)asprintf(&msg, "RegisterNatives failed for '%s'; aborting...", className);
            env->FatalError(msg);
        }
    }

    /**
     * Returns the int fd from a java.io.FileDescriptor.
     */
    static inline int jniGetFDFromFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
        ScopedLocalRef<jclass> localClass(env, env->FindClass("java/io/FileDescriptor"));
#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
        static jfieldID fid = env->GetFieldID(localClass.get(), "descriptor", "I");
#else /* !ANDROID || CONSCRYPT_OPENJDK */
        static jfieldID fid = env->GetFieldID(localClass.get(), "fd", "I");
#endif
        if (fileDescriptor != nullptr) {
            return env->GetIntField(fileDescriptor, fid);
        } else {
            return -1;
        }
    }

    /**
     * Returns true if the VM's JNI GetByteArrayElements method is likely to create a copy when
     * invoked on an array of the provided size.
     */
    static inline bool isGetByteArrayElementsLikelyToReturnACopy(size_t size) {
#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
        // ART's GetByteArrayElements creates copies only for arrays smaller than 12 kB.
        return size <= 12 * 1024;
#else
        (void)size;
        // On OpenJDK based VMs GetByteArrayElements appears to always create a copy.
        return true;
#endif
    }
};

}  // namespace conscrypt

#endif  // CONSCRYPT_JNIUTIL_H_