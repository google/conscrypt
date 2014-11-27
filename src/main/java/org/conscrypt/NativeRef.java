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
}