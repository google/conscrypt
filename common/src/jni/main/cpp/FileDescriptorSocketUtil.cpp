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

#include "FileDescriptorSocketUtil.h"

#include "BioInputStream.h"
#include "BioOutputStream.h"
#include "Errors.h"

using namespace conscrypt;

static int bio_create(BIO *b) {
    b->init = 1;
    b->num = 0;
    b->ptr = nullptr;
    b->flags = 0;
    return 1;
}

static int bio_free(BIO *b) {
    if (b == nullptr) {
        return 0;
    }

    if (b->ptr != nullptr) {
        delete static_cast<BioStream*>(b->ptr);
        b->ptr = nullptr;
    }

    b->init = 0;
    b->flags = 0;
    return 1;
}

static long bio_ctrl(BIO *b, int cmd, long, void *) {
    BioStream* stream = static_cast<BioStream*>(b->ptr);

    switch (cmd) {
    case BIO_CTRL_EOF:
        return stream->isEof() ? 1 : 0;
    case BIO_CTRL_FLUSH:
        return stream->flush();
    default:
        return 0;
    }
}

static int bio_read(BIO *b, char *buf, int len) {
    BIO_clear_retry_flags(b);
    BioInputStream* stream = static_cast<BioInputStream*>(b->ptr);
    int ret = stream->read(buf, len);
    if (ret == 0) {
        if (stream->isFinite()) {
            return 0;
        }
        // If the BioInputStream is not finite then EOF doesn't mean that
        // there's nothing more coming.
        BIO_set_retry_read(b);
        return -1;
    }
    return ret;
}

static int bio_write(BIO *b, const char *buf, int len) {
    BIO_clear_retry_flags(b);
    BioOutputStream* stream = static_cast<BioOutputStream*>(b->ptr);
    return stream->write(buf, len);
}

static int bio_puts(BIO *b, const char *buf) {
    BioOutputStream* stream = static_cast<BioOutputStream*>(b->ptr);
    return stream->write(buf, static_cast<int>(strlen(buf)));
}

static int bio_gets(BIO *b, char *buf, int len) {
    BioInputStream* stream = static_cast<BioInputStream*>(b->ptr);
    return stream->gets(buf, len);
}

static BIO_METHOD stream_bio_method = {
        (100 | 0x0400), /* source/sink BIO */
        "InputStream/OutputStream BIO",
        bio_write,      /* bio_write */
        bio_read,       /* bio_read */
        bio_puts,       /* bio_puts */
        bio_gets,       /* bio_gets */
        bio_ctrl,       /* bio_ctrl */
        bio_create,     /* bio_create */
        bio_free,       /* bio_free */
        nullptr,        /* no bio_callback_ctrl */
};

jlong FileDescriptorSocketUtil::createBioInputStream(JNIEnv* env,
                                                     jobject streamObj,
                                                     jboolean isFinite) {
    JNI_TRACE("create_BIO_InputStream(%p)", streamObj);

    if (streamObj == nullptr) {
        Errors::jniThrowNullPointerException(env, "stream == null");
        return 0;
    }

    bssl::UniquePtr<BIO> bio(BIO_new(&stream_bio_method));
    if (bio.get() == nullptr) {
        return 0;
    }

    (new BioInputStream(streamObj, isFinite == JNI_TRUE))->assignTo(bio.get());

    JNI_TRACE("create_BIO_InputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}

jlong FileDescriptorSocketUtil::createBioOutputStream(JNIEnv* env, jobject streamObj) {
    JNI_TRACE("create_BIO_OutputStream(%p)", streamObj);

    if (streamObj == nullptr) {
        Errors::jniThrowNullPointerException(env, "stream == null");
        return 0;
    }

    bssl::UniquePtr<BIO> bio(BIO_new(&stream_bio_method));
    if (bio.get() == nullptr) {
        return 0;
    }

    (new BioOutputStream(streamObj))->assignTo(bio.get());

    JNI_TRACE("create_BIO_OutputStream(%p) => %p", streamObj, bio.get());
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(bio.release()));
}
