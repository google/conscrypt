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

#include "JniConstants.h"

using namespace conscrypt;

JavaVM* JniConstants::gJavaVM;
jclass JniConstants::cryptoUpcallsClass;
jclass JniConstants::openSslInputStreamClass;
jclass JniConstants::nativeRefClass;

jclass JniConstants::byteArrayClass;
jclass JniConstants::calendarClass;
jclass JniConstants::objectClass;
jclass JniConstants::objectArrayClass;
jclass JniConstants::integerClass;
jclass JniConstants::inputStreamClass;
jclass JniConstants::outputStreamClass;
jclass JniConstants::stringClass;

jfieldID JniConstants::nativeRef_context;

jmethodID JniConstants::calendar_setMethod;
jmethodID JniConstants::inputStream_readMethod;
jmethodID JniConstants::integer_valueOfMethod;
jmethodID JniConstants::openSslInputStream_readLineMethod;
jmethodID JniConstants::outputStream_writeMethod;
jmethodID JniConstants::outputStream_flushMethod;

void JniConstants::init(JavaVM *vm, JNIEnv *env) {
    gJavaVM = vm;

    byteArrayClass = findClass(env, "[B");
    calendarClass = findClass(env, "java/util/Calendar");
    inputStreamClass = findClass(env, "java/io/InputStream");
    integerClass = findClass(env, "java/lang/Integer");
    objectClass = findClass(env, "java/lang/Object");
    objectArrayClass = findClass(env, "[Ljava/lang/Object;");
    outputStreamClass = findClass(env, "java/io/OutputStream");
    stringClass = findClass(env, "java/lang/String");

    cryptoUpcallsClass = getGlobalRefToClass(env,
                CONSCRYPT_SYMBOL_PREFIX "org/conscrypt/CryptoUpcalls");
    nativeRefClass = getGlobalRefToClass(env,
            CONSCRYPT_SYMBOL_PREFIX "org/conscrypt/NativeRef");
    openSslInputStreamClass = getGlobalRefToClass(env,
            CONSCRYPT_SYMBOL_PREFIX "org/conscrypt/OpenSSLBIOInputStream");

    nativeRef_context = getFieldRef(env, nativeRefClass, "context", "J");

    calendar_setMethod = getMethodRef(env, calendarClass, "set", "(IIIIII)V");
    inputStream_readMethod = getMethodRef(env, inputStreamClass, "read", "([B)I");
    integer_valueOfMethod = env->GetStaticMethodID(integerClass, "valueOf",
            "(I)Ljava/lang/Integer;");
    openSslInputStream_readLineMethod = getMethodRef(env, openSslInputStreamClass, "gets",
            "([B)I");
    outputStream_writeMethod = getMethodRef(env, outputStreamClass, "write", "([B)V");
    outputStream_flushMethod = getMethodRef(env, outputStreamClass, "flush", "()V");
}
