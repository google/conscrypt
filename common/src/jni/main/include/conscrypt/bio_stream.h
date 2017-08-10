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

#ifndef CONSCRYPT_BIO_STREAM_H_
#define CONSCRYPT_BIO_STREAM_H_

#include <jni.h>

#include <conscrypt/jniutil.h>
#include <conscrypt/trace.h>

namespace conscrypt {

/**
 * BIO for InputStream
 */
class BioStream {
 public:
    explicit BioStream(jobject stream) : mEof(false) {
        JNIEnv* env = jniutil::getJNIEnv();
        mStream = env->NewGlobalRef(stream);
    }

    ~BioStream() {
        JNIEnv* env = jniutil::getJNIEnv();

        env->DeleteGlobalRef(mStream);
    }

    bool isEof() const {
        JNI_TRACE("isEof? %s", mEof ? "yes" : "no");
        return mEof;
    }

    int flush() {
        JNIEnv* env = jniutil::getJNIEnv();
        if (env == nullptr) {
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BioStream::flush called with pending exception");
            return -1;
        }

        env->CallVoidMethod(mStream, jniutil::outputStream_flushMethod);
        if (env->ExceptionCheck()) {
            return -1;
        }

        return 1;
    }

 protected:
    jobject getStream() {
        return mStream;
    }

    void setEof(bool eof) {
        mEof = eof;
    }

 private:
    jobject mStream;
    bool mEof;
};

}  // namespace conscrypt

#endif  // CONSCRYPT_BIO_STREAM_H_
