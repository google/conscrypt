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

#ifndef CONSCRYPT_BIO_OUTPUT_STREAM_H_
#define CONSCRYPT_BIO_OUTPUT_STREAM_H_

#include <jni.h>

#include <conscrypt/bio_stream.h>

namespace conscrypt {

class BioOutputStream : public BioStream {
 public:
    explicit BioOutputStream(jobject stream) : BioStream(stream) {}

    int write(const char* buf, int len) {
        JNIEnv* env = jniutil::getJNIEnv();
        if (env == nullptr) {
            JNI_TRACE("BioOutputStream::write => could not get JNIEnv");
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BioOutputStream::write => called with pending exception");
            return -1;
        }

        ScopedLocalRef<jbyteArray> javaBytes(env, env->NewByteArray(len));
        if (javaBytes.get() == nullptr) {
            JNI_TRACE("BioOutputStream::write => failed call to NewByteArray");
            return -1;
        }

        env->SetByteArrayRegion(javaBytes.get(), 0, len, reinterpret_cast<const jbyte*>(buf));

        env->CallVoidMethod(getStream(), jniutil::outputStream_writeMethod, javaBytes.get());
        if (env->ExceptionCheck()) {
            JNI_TRACE("BioOutputStream::write => failed call to OutputStream#write");
            return -1;
        }

        return len;
    }
};

}  // namespace conscrypt

#endif  // CONSCRYPT_BIO_OUTPUT_STREAM_H_
