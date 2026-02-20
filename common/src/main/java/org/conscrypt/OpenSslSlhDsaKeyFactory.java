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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/** An implementation of a {@link KeyFactorySpi} for SLH-DSL keys based on BoringSSL. */
@Internal
public final class OpenSslSlhDsaKeyFactory extends KeyFactorySpi {
    public OpenSslSlhDsaKeyFactory() {}

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSslSlhDsaPublicKey((EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("Currently only EncodedKeySpec is supported; was "
                                          + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSslSlhDsaPrivateKey((EncodedKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("Currently only EncodedKeySpec is supported; was "
                                          + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("key == null");
        }
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (key instanceof OpenSslSlhDsaPublicKey) {
            OpenSslSlhDsaPublicKey conscryptKey = (OpenSslSlhDsaPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                throw new UnsupportedOperationException(
                        "X509EncodedKeySpec is currently not supported");
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslSlhDsaPrivateKey) {
            OpenSslSlhDsaPrivateKey conscryptKey = (OpenSslSlhDsaPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                throw new UnsupportedOperationException(
                        "PKCS8EncodedKeySpec is currently not supported");
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        }
        throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                                          + key.getClass().getName()
                                          + ", keySpec=" + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if ((key instanceof OpenSslSlhDsaPublicKey) || (key instanceof OpenSslSlhDsaPrivateKey)) {
            return key;
        }
        throw new InvalidKeyException(
                "Key must be OpenSslSlhDsaPublicKey or OpenSslSlhDsaPrivateKey");
    }
}
