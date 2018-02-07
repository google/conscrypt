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

#ifndef CONSCRYPT_SSL_ERROR_H_
#define CONSCRYPT_SSL_ERROR_H_

#include <openssl/ssl.h>

namespace conscrypt {

/**
 * Manages the freeing of the SSL error stack. This allows you to
 * instantiate this object during an SSL call that may fail and not worry
 * about manually calling ERR_clear_error() later.
 *
 * As an optimization, you can also call .release() for passing as an
 * argument to things that free the error stack state as a side-effect.
 */
class SslError {
 public:
    SslError() : sslError_(SSL_ERROR_NONE), released_(false) {}

    SslError(SSL* ssl, int returnCode) : sslError_(SSL_ERROR_NONE), released_(false) {
        reset(ssl, returnCode);
    }

    ~SslError() {
        if (!released_ && sslError_ != SSL_ERROR_NONE) {
            ERR_clear_error();
        }
    }

    int get() const {
        return sslError_;
    }

    void reset(SSL* ssl, int returnCode) {
        if (returnCode <= 0) {
            sslError_ = SSL_get_error(ssl, returnCode);
        } else {
            sslError_ = SSL_ERROR_NONE;
        }
    }

    int release() {
        released_ = true;
        return sslError_;
    }

 private:
    int sslError_;
    bool released_;
};

}  // namespace conscrypt

#endif  // CONSCRYPT_SSL_ERROR_H_
