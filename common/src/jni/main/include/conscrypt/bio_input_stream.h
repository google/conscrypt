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

#ifndef CONSCRYPT_BIO_INPUT_STREAM_H_
#define CONSCRYPT_BIO_INPUT_STREAM_H_

#include <jni.h>
#include <openssl/ssl.h>

#include <conscrypt/bio_stream.h>
#include <nativehelper/scoped_local_ref.h>

namespace conscrypt {

class BioInputStream : public BioStream {
 public:
    BioInputStream(jobject stream, bool isFinite) : BioStream(stream), isFinite_(isFinite) {}

    int read(char *buf, int len) {
        return read_internal(buf, len, jniutil::inputStream_readMethod);
    }

    int gets(char *buf, int len) {
        if (len > PEM_LINE_LENGTH) {
            len = PEM_LINE_LENGTH;
        }

        int read = read_internal(buf, len - 1, jniutil::openSslInputStream_readLineMethod);
        buf[read] = '\0';
        JNI_TRACE("BIO::gets \"%s\"", buf);
        return read;
    }

    bool isFinite() const {
        return isFinite_;
    }

 private:
    const bool isFinite_;

    int read_internal(char *buf, int len, jmethodID method) {
        JNIEnv *env = jniutil::getJNIEnv();
        if (env == nullptr) {
            JNI_TRACE("BioInputStream::read could not get JNIEnv");
            return -1;
        }

        if (env->ExceptionCheck()) {
            JNI_TRACE("BioInputStream::read called with pending exception");
            return -1;
        }

        ScopedLocalRef<jbyteArray> javaBytes(env, env->NewByteArray(len));
        if (javaBytes.get() == nullptr) {
            JNI_TRACE("BioInputStream::read failed call to NewByteArray");
            return -1;
        }

        jint read = env->CallIntMethod(getStream(), method, javaBytes.get());
        if (env->ExceptionCheck()) {
            JNI_TRACE("BioInputStream::read failed call to InputStream#read");
            return -1;
        }

        /* Java uses -1 to indicate EOF condition. */
        if (read == -1) {
            setEof(true);
            read = 0;
        } else if (read > 0) {
            env->GetByteArrayRegion(javaBytes.get(), 0, read, reinterpret_cast<jbyte *>(buf));
        }

        return read;
    }

 public:
    /** Length of PEM-encoded line (64) plus CR plus NUL */
    static const int PEM_LINE_LENGTH = 66;
};

}  // namespace conscrypt

#endif  // CONSCRYPT_BIO_INPUT_STREAM_H_
