/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import static org.conscrypt.TestUtils.conscryptClass;

import java.lang.reflect.Method;

public class HpkeTestingContextSenderHelper extends HpkeContextSenderHelper {
    private final byte[] skE;

    public HpkeTestingContextSenderHelper(byte[] skE) {
        this.skE = skE;
    }

    @Override
    public Object[] setupBase(int kem, int kdf, int aead, byte[] encodedKey, byte[] info) {
        try {
            final Class<?> nativeCryptoClass = conscryptClass("NativeCrypto");
            final Method method = nativeCryptoClass.getDeclaredMethod(
                    /* name = */ "EVP_HPKE_CTX_setup_sender_with_seed_for_testing",
                    /* parameterType = */ int.class,
                    /* parameterType = */ int.class,
                    /* parameterType = */ int.class,
                    /* parameterType = */ byte[].class,
                    /* parameterType = */ byte[].class,
                    /* parameterType = */ byte[].class);
            method.setAccessible(true);
            return (Object[]) method.invoke(
                    nativeCryptoClass, kem, kdf, aead, encodedKey, info, skE);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Error while calling EVP_HPKE_CTX_setup_sender_with_seed_for_testing", e);
        }
    }
}
