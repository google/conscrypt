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
public final class OpenSSLECDHKeyAgreement extends OpenSSLBaseDHKeyAgreement<OpenSSLKey> {
    public OpenSSLECDHKeyAgreement() {
    }

    @Override
    protected OpenSSLKey convertPublicKey(PublicKey key) throws InvalidKeyException {
        return OpenSSLKey.fromPublicKey(key);
    }

    @Override
    protected OpenSSLKey convertPrivateKey(PrivateKey key) throws InvalidKeyException {
        return OpenSSLKey.fromPrivateKey(key);
    }

    @Override
    protected int computeKey(byte[] buffer, OpenSSLKey theirPublicKey, OpenSSLKey ourPrivateKey) throws InvalidKeyException {
        return NativeCrypto.ECDH_compute_key(
                buffer,
                0,
                theirPublicKey.getNativeRef(),
                ourPrivateKey.getNativeRef());
    }

    @Override
    protected int getOutputSize(OpenSSLKey openSslKey) {
        int fieldSizeBits = NativeCrypto.EC_GROUP_get_degree(new NativeRef.EC_GROUP(
                NativeCrypto.EC_KEY_get1_group(openSslKey.getNativeRef())));
        return (fieldSizeBits + 7) / 8;
    }
}
