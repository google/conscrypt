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
public abstract class NativeRef {
    final long context;

    public NativeRef(long ctx) {
        if (ctx == 0) {
            throw new NullPointerException("ctx == 0");
        }

        this.context = ctx;
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

    public static class EC_GROUP extends NativeRef {
        public EC_GROUP(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EC_GROUP_clear_free(context);
            } finally {
                super.finalize();
            }
        }
    }

    public static class EC_POINT extends NativeRef {
        public EC_POINT(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EC_POINT_clear_free(context);
            } finally {
                super.finalize();
            }
        }
    }

    public static class EVP_AEAD_CTX extends NativeRef {
        public EVP_AEAD_CTX(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EVP_AEAD_CTX_cleanup(context);
            } finally {
                super.finalize();
            }
        }
    }

    public static class EVP_CIPHER_CTX extends NativeRef {
        public EVP_CIPHER_CTX(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EVP_CIPHER_CTX_free(context);
            } finally {
                super.finalize();
            }
        }
    }

    public static class EVP_MD_CTX extends NativeRef {
        public EVP_MD_CTX(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EVP_MD_CTX_destroy(context);
            } finally {
                super.finalize();
            }
        }
    }

    public static class EVP_PKEY extends NativeRef {
        public EVP_PKEY(long ctx) {
            super(ctx);
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                NativeCrypto.EVP_PKEY_free(context);
            } finally {
                super.finalize();
            }
        }
    }
}
