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

#ifndef CONSCRYPT_JNICONSTANTS_H_
#define CONSCRYPT_JNICONSTANTS_H_

#include "macros.h"
#include "ScopedLocalRef.h"
#include <jni.h>
#include <stdlib.h>

namespace conscrypt {

class JniConstants {
private:
    JniConstants() {}
    ~JniConstants() {}

public:

    /**
     * Initializes the JNI constants from the environment.
     */
    static void init(JavaVM *vm, JNIEnv *env);

    /**
     * Obtains the current thread's JNIEnv
     */
    static inline JNIEnv* getJNIEnv() {
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

    static inline jmethodID getMethodRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
        jmethodID localMethod = env->GetMethodID(clazz, name, sig);
        if (localMethod == nullptr) {
            ALOGE("could not find method %s", name);
            abort();
        }
        return localMethod;
    }

    static inline jfieldID getFieldRef(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
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

public:

    static JavaVM* gJavaVM;
    static jclass cryptoUpcallsClass;
    static jclass openSslInputStreamClass;
    static jclass nativeRefClass;

    static jclass byteArrayClass;
    static jclass calendarClass;
    static jclass objectClass;
    static jclass objectArrayClass;
    static jclass integerClass;
    static jclass inputStreamClass;
    static jclass outputStreamClass;
    static jclass stringClass;

    static jfieldID nativeRef_context;

    static jmethodID calendar_setMethod;
    static jmethodID inputStream_readMethod;
    static jmethodID integer_valueOfMethod;
    static jmethodID openSslInputStream_readLineMethod;
    static jmethodID outputStream_writeMethod;
    static jmethodID outputStream_flushMethod;
};

} // namespace conscrypt

#endif  // CONSCRYPT_JNICONSTANTS_H_
