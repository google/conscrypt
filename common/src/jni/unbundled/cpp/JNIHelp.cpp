/*
 * Copyright (C) 2006 The Android Open Source Project
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

#define LOG_TAG "JNIHelp"

#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
// We want the XSI-compliant strerror_r (it's more portable across NDK versions,
// and the only one available until android-23), not the GNU one. We haven't
// actually defined _GNU_SOURCE ourselves, but the compiler adds it
// automatically when building C++.
//
// Including this header out of the normal order to make sure we import it the
// right way.
#undef _GNU_SOURCE
#include <string.h>

// OTOH, we need to have _GNU_SOURCE defined to pick up asprintf from stdio.h.
#define _GNU_SOURCE
#include <stdio.h>

#include <android/log.h>

#else  /* !ANDROID || CONSCRYPT_OPENJDK */

#include <stdio.h>
#include <string.h>

#endif /* !ANDROID || CONSCRYPT_OPENJDK */

#include "JNIHelp.h"
#include "log_compat.h"

#include <stdlib.h>
#include <assert.h>

/**
 * Equivalent to ScopedLocalRef, but slightly more powerful.
 */
template<typename T>
class scoped_local_ref {
public:
    scoped_local_ref(JNIEnv* env, T localRef = nullptr)
    : mEnv(env), mLocalRef(localRef)
    {
    }

    ~scoped_local_ref() {
        reset();
    }

    void reset(T localRef = nullptr) {
        if (mLocalRef != nullptr) {
            mEnv->DeleteLocalRef(mLocalRef);
            mLocalRef = localRef;
        }
    }

    T get() const {
        return mLocalRef;
    }

private:
    JNIEnv* mEnv;
    T mLocalRef;

    // Disallow copy and assignment.
    scoped_local_ref(const scoped_local_ref&);
    void operator=(const scoped_local_ref&);
};

extern "C" int jniRegisterNativeMethods(C_JNIEnv* c_env, const char* className,
    const JNINativeMethod* gMethods, int numMethods)
{
    JNIEnv* env = reinterpret_cast<JNIEnv*>(c_env);

    ALOGV("Registering %s's %d native methods...", className, numMethods);

    scoped_local_ref<jclass> c(env, env->FindClass(className));
    if (c.get() == nullptr) {
        char* msg;
        (void) asprintf(&msg, "Native registration unable to find class '%s'; aborting...", className);
        env->FatalError(msg);
    }

    if (env->RegisterNatives(c.get(), gMethods, numMethods) < 0) {
        char* msg;
        (void) asprintf(&msg, "RegisterNatives failed for '%s'; aborting...", className);
        env->FatalError(msg);
    }

    return 0;
}

#ifdef __cplusplus
extern "C"
#endif
int jniThrowException(C_JNIEnv* c_env, const char* className, const char* msg) {
    JNIEnv* env = reinterpret_cast<JNIEnv*>(c_env);
    jclass exceptionClass = env->FindClass(className);

    if (exceptionClass == nullptr) {
        ALOGD("Unable to find exception class %s", className);
        /* ClassNotFoundException now pending */
        return -1;
    }

    if (env->ThrowNew(exceptionClass, msg) != JNI_OK) {
        ALOGD("Failed throwing '%s' '%s'", className, msg);
        /* an exception, most likely OOM, will now be pending */
        return -1;
    }

    env->DeleteLocalRef(exceptionClass);
    return 0;
}

int jniThrowExceptionFmt(C_JNIEnv* env, const char* className, const char* fmt, va_list args) {
    char msgBuf[512];
    vsnprintf(msgBuf, sizeof(msgBuf), fmt, args);
    return jniThrowException(env, className, msgBuf);
}

int jniThrowNullPointerException(C_JNIEnv* env, const char* msg) {
    return jniThrowException(env, "java/lang/NullPointerException", msg);
}

int jniThrowRuntimeException(C_JNIEnv* env, const char* msg) {
    return jniThrowException(env, "java/lang/RuntimeException", msg);
}

int jniThrowIOException(C_JNIEnv* env, int errnum) {
    char buffer[80];
    const char* message = jniStrError(errnum, buffer, sizeof(buffer));
    return jniThrowException(env, "java/io/IOException", message);
}

const char* jniStrError(int errnum, char* buf, size_t buflen) {
#if __GLIBC__
    // Note: glibc has a nonstandard strerror_r that returns char* rather than POSIX's int.
    // char *strerror_r(int errnum, char *buf, size_t n);
    return strerror_r(errnum, buf, buflen);
#else
    int rc = strerror_r(errnum, buf, buflen);
    if (rc != 0) {
        // (POSIX only guarantees a value other than 0. The safest
        // way to implement this function is to use C++ and overload on the
        // type of strerror_r to accurately distinguish GNU from POSIX.)
        snprintf(buf, buflen, "errno %d", errnum);
    }
    return buf;
#endif
}

int jniGetFDFromFileDescriptor(C_JNIEnv* c_env, jobject fileDescriptor) {
    JNIEnv* env = reinterpret_cast<JNIEnv*>(c_env);
    scoped_local_ref<jclass> localClass(env, env->FindClass("java/io/FileDescriptor"));
#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
    static jfieldID fid = env->GetFieldID(localClass.get(), "descriptor", "I");
#else  /* !ANDROID || CONSCRYPT_OPENJDK */
    static jfieldID fid = env->GetFieldID(localClass.get(), "fd", "I");
#endif
    if (fileDescriptor != nullptr) {
        return env->GetIntField(fileDescriptor, fid);
    } else {
        return -1;
    }
}
