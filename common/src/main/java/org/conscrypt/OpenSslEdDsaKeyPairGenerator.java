/*
 * Copyright 2025 The Android Open Source Project
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * An implementation of {@link KeyPairGenerator} for XDH keys which uses BoringSSL to perform all
 * the operations. This only supports EdDSA keys.
 */
@Internal
public final class OpenSslEdDsaKeyPairGenerator extends KeyPairGenerator {
    private static final String ALGORITHM = "EdDSA";

    public OpenSslEdDsaKeyPairGenerator() {
        super(ALGORITHM);
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] publicKeyBytes = new byte[32];
        byte[] privateKeyBytes = new byte[64];

        NativeCrypto.ED25519_keypair(publicKeyBytes, privateKeyBytes);

        // BoringSSL uses a 64-byte private key. We only need the seed, which is the first 32 bytes.
        byte[] privateKeySeed = Arrays.copyOf(privateKeyBytes, 32);

        return new KeyPair(new OpenSslEdDsaPublicKey(publicKeyBytes),
                           new OpenSslEdDsaPrivateKey(privateKeySeed));
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != 255) {
            throw new IllegalArgumentException("EdDSA only supports key size 255");
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec param, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "No AlgorithmParameterSpec classes are supported");
    }
}
