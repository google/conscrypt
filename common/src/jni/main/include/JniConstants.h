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

#include <jni.h>
#include "JniUtil.h"

namespace conscrypt {

class JniConstants {
private:
    JniConstants() {}
    ~JniConstants() {}

public:
    /**
     * Initializes the JNI constants from the environment.
     */
    static void init(JavaVM* vm, JNIEnv* env);

    /**
     * Obtains the current thread's JNIEnv
     */
    static inline JNIEnv* getJNIEnv() {
        return JniUtil::getJNIEnv(gJavaVM);
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

}  // namespace conscrypt

#endif  // CONSCRYPT_JNICONSTANTS_H_
