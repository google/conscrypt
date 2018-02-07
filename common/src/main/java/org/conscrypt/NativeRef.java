/*
 * Copyright 2014 The Android Open Source Project
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

package org.conscrypt;

/**
 * Used to hold onto native OpenSSL references and run finalization on those
 * objects. Individual types must subclass this and implement finalizer.
 */
abstract class NativeRef {
    final long context;

    NativeRef(long context) {
        if (context == 0) {
            throw new NullPointerException("context == 0");
        }

        this.context = context;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof NativeRef)) {
            return false;
        }

        return ((NativeRef) o).context == context;
    }

    @Override
    public int hashCode() {
        return (int) context;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (context != 0) {
                doFree(context);
            }
        } finally {
            super.finalize();
        }
    }

    abstract void doFree(long context);

    static final class EC_GROUP extends NativeRef {
        EC_GROUP(long ctx) {
            super(ctx);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EC_GROUP_clear_free(context);
        }
    }

    static final class EC_POINT extends NativeRef {
        EC_POINT(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EC_POINT_clear_free(context);
        }
    }

    static final class EVP_CIPHER_CTX extends NativeRef {
        EVP_CIPHER_CTX(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EVP_CIPHER_CTX_free(context);
        }
    }

    static final class EVP_MD_CTX extends NativeRef {
        EVP_MD_CTX(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EVP_MD_CTX_destroy(context);
        }
    }

    static final class EVP_PKEY extends NativeRef {
        EVP_PKEY(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EVP_PKEY_free(context);
        }
    }

    static final class EVP_PKEY_CTX extends NativeRef {
        EVP_PKEY_CTX(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.EVP_PKEY_CTX_free(context);
        }
    }

    static final class HMAC_CTX extends NativeRef {
        HMAC_CTX(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.HMAC_CTX_free(context);
        }
    }

    static final class SSL_SESSION extends NativeRef {
        SSL_SESSION(long nativePointer) {
            super(nativePointer);
        }

        @Override
        void doFree(long context) {
            NativeCrypto.SSL_SESSION_free(context);
        }
    }
}
