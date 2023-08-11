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

/**
 * Separating {@link HpkeContextSender} logic for testing purposes. Testing could override these
 * functions to call different implementations meant for testing as well.
 */
@Internal
public class HpkeContextSenderHelper {
    /**
     * Setup sender with base mode. Delegates the setup work to BoringSSL.
     *
     * @param kem kem decimal value representation, {@link HpkeSuite.KEM#getId()}
     * @param kdf kdf decimal value representation, {@link HpkeSuite.KDF#getId()}
     * @param aead aead decimal value representation, {@link HpkeSuite.AEAD#getId()}
     * @param publicKey encoded public key value
     * @param info optional application-supplied information
     * @return object array with 2 elements, the HPKE context [0] and the encapsulated key [1]
     */
    @Internal
    public Object[] setupBase(int kem, int kdf, int aead, byte[] publicKey, byte[] info) {
        Preconditions.checkNotNull(publicKey, "publicKey");
        return NativeCrypto.EVP_HPKE_CTX_setup_sender(kem, kdf, aead, publicKey, info);
    }
}
