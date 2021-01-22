/*
 * Copyright (C) 2013 The Android Open Source Project
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

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Elliptic Curve Diffie-Hellman key agreement backed by the OpenSSL engine.
 */
@Internal
public final class OpenSSLXDHKeyAgreement extends OpenSSLBaseDHKeyAgreement<byte[]> {
    public OpenSSLXDHKeyAgreement() {
    }

    @Override
    protected byte[] convertPublicKey(PublicKey key) throws InvalidKeyException {
        if (!(key instanceof OpenSSLX25519PublicKey)) {
            throw new InvalidKeyException("Only OpenSSLX25519PublicKey accepted");
        }

        return ((OpenSSLX25519PublicKey) key).getU();
    }

    @Override
    protected byte[] convertPrivateKey(PrivateKey key) throws InvalidKeyException {
        if (!(key instanceof OpenSSLX25519PrivateKey)) {
            throw new InvalidKeyException("Only OpenSSLX25519PublicKey accepted");
        }

        return ((OpenSSLX25519PrivateKey) key).getU();
    }

    @Override
    protected int computeKey(byte[] buffer, byte[] theirPublicKey, byte[] ourPrivateKey) throws InvalidKeyException {
        if (!NativeCrypto.X25519(
                buffer,
                ourPrivateKey,
                theirPublicKey)) {
            throw new InvalidKeyException("Error running X25519");
        }

        return OpenSSLX25519Key.X25519_KEY_SIZE_BYTES;
    }

    @Override
    protected int getOutputSize(byte[] key) {
        // We only support X25519 which is 32-byte (256-bit)
        return OpenSSLX25519Key.X25519_KEY_SIZE_BYTES;
    }
}
