/*
 * Copyright (C) 2025 The Android Open Source Project
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

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * An implementation of {@link KeyPairGenerator} for XWING keys which uses BoringSSL to perform all
 * the operations.
 */
@Internal
public final class OpenSslXwingKeyPairGenerator extends KeyPairGenerator {
    public OpenSslXwingKeyPairGenerator() {
        super("XWING");
    }

    @Override
    public void initialize(int bits) throws InvalidParameterException {
        if (bits != -1) {
            throw new InvalidParameterException("XWING only supports -1 for bits");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] privateKeyBytes = new byte[OpenSslXwingPrivateKey.PRIVATE_KEY_SIZE_BYTES];
        NativeCrypto.RAND_bytes(privateKeyBytes);
        byte[] publicKeyBytes = NativeCrypto.XWING_public_key_from_seed(privateKeyBytes);
        return new KeyPair(new OpenSslXwingPublicKey(publicKeyBytes),
                           new OpenSslXwingPrivateKey(privateKeyBytes));
    }
}
