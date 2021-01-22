/*
 * Copyright (C) 2012 The Android Open Source Project
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

/**
 * An implementation of {@link KeyPairGenerator} for XDH keys which uses BoringSSL to perform all the
 * operations. This only supports X25519 keys.
 */
@Internal
public final class OpenSSLXDHKeyPairGenerator extends KeyPairGenerator {
    private static final String ALGORITHM = "XDH";

    public OpenSSLXDHKeyPairGenerator() {
        super(ALGORITHM);
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] publicKeyBytes = new byte[OpenSSLX25519Key.X25519_KEY_SIZE_BYTES];
        byte[] privateKeyBytes = new byte[OpenSSLX25519Key.X25519_KEY_SIZE_BYTES];

        NativeCrypto.X25519_keypair(publicKeyBytes, privateKeyBytes);

        return new KeyPair(new OpenSSLX25519PublicKey(publicKeyBytes), new OpenSSLX25519PrivateKey(privateKeyBytes));
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
    }

    @Override
    public void initialize(AlgorithmParameterSpec param, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "No AlgorithmParameterSpec classes are supported");
    }
}
