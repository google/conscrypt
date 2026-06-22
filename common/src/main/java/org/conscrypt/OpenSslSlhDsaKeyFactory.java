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
import java.util.Arrays;

/** An implementation of a {@link KeyFactorySpi} for SLH-DSL keys based on BoringSSL. */
@Internal
public final class OpenSslSlhDsaKeyFactory extends KeyFactorySpi {
    // X.509 format preamble for SLH-DSA-SHA2-128S.
    static final byte[] x509Preamble = new byte[] {
            (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x09,
            (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
            (byte) 0x04, (byte) 0x03, (byte) 0x14, (byte) 0x03, (byte) 0x21, (byte) 0x00};

    // PKCS#8 format preamble for SLH-DSA-SHA2-128S.
    static final byte[] pkcs8Preamble =
            new byte[] {(byte) 0x30, (byte) 0x52, (byte) 0x02, (byte) 0x01, (byte) 0x00,
                        (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x09, (byte) 0x60,
                        (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
                        (byte) 0x04, (byte) 0x03, (byte) 0x14, (byte) 0x04, (byte) 0x40};

    public OpenSslSlhDsaKeyFactory() {}

    private OpenSslSlhDsaPublicKey makePublicKeyFromRaw(byte[] raw) throws InvalidKeySpecException {
        if (raw.length != OpenSslSlhDsaPublicKey.PUBLIC_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid raw public key length: " + raw.length
                                              + " != "
                                              + OpenSslSlhDsaPublicKey.PUBLIC_KEY_SIZE_BYTES);
        }
        try {
            return new OpenSslSlhDsaPublicKey(raw);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid raw public key", e);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (!(keySpec instanceof EncodedKeySpec)) {
            throw new InvalidKeySpecException("Currently only EncodedKeySpec is supported; was "
                                              + keySpec.getClass().getName());
        }
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec) keySpec;
        if ("raw".equalsIgnoreCase(encodedKeySpec.getFormat())) {
            byte[] raw = encodedKeySpec.getEncoded();
            return makePublicKeyFromRaw(raw);
        }
        if (!encodedKeySpec.getFormat().equals("X.509")) {
            throw new InvalidKeySpecException("Encoding must be in X.509 format");
        }
        byte[] encoded = encodedKeySpec.getEncoded();
        if (ArrayUtils.startsWith(encoded, x509Preamble)) {
            byte[] raw = Arrays.copyOfRange(encoded, x509Preamble.length, encoded.length);
            return makePublicKeyFromRaw(raw);
        } else {
            throw new InvalidKeySpecException(
                    "Only X.509 format for SLH-DSA-SHA2-128S is supported");
        }
    }

    private OpenSslSlhDsaPrivateKey makePrivateKeyFromRaw(byte[] raw)
            throws InvalidKeySpecException {
        if (raw.length != OpenSslSlhDsaPrivateKey.PRIVATE_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid raw private key length: " + raw.length
                                              + " != "
                                              + OpenSslSlhDsaPrivateKey.PRIVATE_KEY_SIZE_BYTES);
        }
        try {
            return new OpenSslSlhDsaPrivateKey(raw);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid raw private key", e);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (!(keySpec instanceof EncodedKeySpec)) {
            throw new InvalidKeySpecException("Currently only EncodedKeySpec is supported; was "
                                              + keySpec.getClass().getName());
        }
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec) keySpec;
        if ("raw".equalsIgnoreCase(encodedKeySpec.getFormat())) {
            byte[] raw = encodedKeySpec.getEncoded();
            return makePrivateKeyFromRaw(raw);
        }
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) {
            throw new InvalidKeySpecException("Encoding must be in PKCS#8 format");
        }
        byte[] encoded = encodedKeySpec.getEncoded();
        if (ArrayUtils.startsWith(encoded, pkcs8Preamble)) {
            byte[] raw = Arrays.copyOfRange(encoded, pkcs8Preamble.length, encoded.length);
            return makePrivateKeyFromRaw(raw);
        } else {
            throw new InvalidKeySpecException(
                    "Only PKCS#8 format for SLH-DSA-SHA2-128S is supported");
        }
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
                @SuppressWarnings("unchecked")
                T result = (T) new X509EncodedKeySpec(key.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslSlhDsaPrivateKey) {
            OpenSslSlhDsaPrivateKey conscryptKey = (OpenSslSlhDsaPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new PKCS8EncodedKeySpec(key.getEncoded());
                return result;
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
        if ((key instanceof PrivateKey) && key.getFormat().equals("PKCS#8")) {
            byte[] encoded = key.getEncoded();
            try {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if ((key instanceof PublicKey) && key.getFormat().equals("X.509")) {
            byte[] encoded = key.getEncoded();
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Unable to translate key into SLH-DSA key");
        }
    }
}
