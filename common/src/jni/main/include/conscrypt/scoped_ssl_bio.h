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

#ifndef CONSCRYPT_SCOPED_SSL_BIO_H_
#define CONSCRYPT_SCOPED_SSL_BIO_H_

#include <openssl/ssl.h>

namespace conscrypt {

/*
 * Sets the read and write BIO for an SSL connection and removes it when it goes out of scope.
 * We hang on to BIO with a JNI GlobalRef and we want to remove them as soon as possible.
 */
class ScopedSslBio {
 public:
    ScopedSslBio(SSL* ssl, BIO* rbio, BIO* wbio) : ssl_(ssl) {
        SSL_set_bio(ssl_, rbio, wbio);
        BIO_up_ref(rbio);
        BIO_up_ref(wbio);
    }

    ~ScopedSslBio() {
        SSL_set_bio(ssl_, nullptr, nullptr);
    }

 private:
    SSL* const ssl_;
};

}  // namespace conscrypt

#endif  // CONSCRYPT_SCOPED_SSL_BIO_H_
