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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
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

/** An implementation of a {@link KeyFactorySpi} for MLDSA keys based on BoringSSL. */
@Internal
public abstract class OpenSslMlDsaKeyFactory extends KeyFactorySpi {
    private final MlDsaAlgorithm algorithm;

    private OpenSslMlDsaKeyFactory(MlDsaAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    abstract boolean supportsAlgorithm(MlDsaAlgorithm algorithm);

    /** ML-DSA */
    public static class MlDsa extends OpenSslMlDsaKeyFactory {
        public MlDsa() {
            super(MlDsaAlgorithm.ML_DSA_65);
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_65)
                    || algorithm.equals(MlDsaAlgorithm.ML_DSA_87);
        }
    }

    static final byte[] x509PreambleMlDsa65 = new byte[] {
            0x30,
            (byte) 0x82,
            0x07,
            (byte) 0xb2,
            0x30,
            0x0b,
            0x06,
            0x09,
            0x60,
            (byte) 0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x03,
            0x12,
            0x03,
            (byte) 0x82,
            0x07,
            (byte) 0xa1,
            0x00,
    };

    static final byte[] x509PreambleMlDsa87 = new byte[] {
            0x30,
            (byte) 0x82,
            0x0a,
            0x32,
            0x30,
            0x0b,
            0x06,
            0x09,
            0x60,
            (byte) 0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x03,
            0x13,
            0x03,
            (byte) 0x82,
            0x0a,
            0x21,
            0x00,
    };

    static final byte[] pkcs8PreambleMlDsa65 = new byte[] {
            0x30, 0x34,
            0x02,
            0x01,
            0x00,
            0x30,
            0x0b,
            0x06,
            0x09,
            0x60,
            (byte) 0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x03,
            0x12,
            0x04,
            0x22,
            (byte) 0x80,
            0x20,
    };

    static final byte[] pkcs8PreambleMlDsa87 = new byte[] {
            0x30,
            0x34,
            0x02,
            0x01,
            0x00,
            0x30,
            0x0b,
            0x06,
            0x09,
            0x60,
            (byte) 0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x03,
            0x13,
            0x04,
            0x22,
            (byte) 0x80,
            0x20,
    };

    /** ML-DSA-65 */
    public static class MlDsa65 extends OpenSslMlDsaKeyFactory {
        public MlDsa65() {
            super(MlDsaAlgorithm.ML_DSA_65);
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_65);
        }
    }

    /** ML-DSA-87 */
    public static class MlDsa87 extends OpenSslMlDsaKeyFactory {
        public MlDsa87() {
            super(MlDsaAlgorithm.ML_DSA_87);
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_87);
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
        if (encodedKeySpec.getFormat().equalsIgnoreCase("raw")) {
            byte[] raw = encodedKeySpec.getEncoded();
            if (raw.length != algorithm.publicKeySize()) {
                throw new InvalidKeySpecException("Invalid raw public key");
            }
            return new OpenSslMlDsaPublicKey(raw, algorithm);
        }
        if (!encodedKeySpec.getFormat().equals("X.509")) {
            throw new InvalidKeySpecException("Encoding must be in X.509 format");
        }
        byte[] encoded = encodedKeySpec.getEncoded();
        byte[] raw;
        MlDsaAlgorithm algorithm;
        if (ArrayUtils.startsWith(encoded, x509PreambleMlDsa65)) {
            int totalLength = x509PreambleMlDsa65.length + 1952;
            if (encoded.length != totalLength) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            raw = Arrays.copyOfRange(encoded, x509PreambleMlDsa65.length, totalLength);
            if (raw.length != 1952) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            algorithm = MlDsaAlgorithm.ML_DSA_65;
        } else if (ArrayUtils.startsWith(encoded, x509PreambleMlDsa87)) {
            int totalLength = x509PreambleMlDsa87.length + 2592;
            if (encoded.length != totalLength) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            raw = Arrays.copyOfRange(encoded, x509PreambleMlDsa65.length, totalLength);
            if (raw.length != 2592) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            algorithm = MlDsaAlgorithm.ML_DSA_87;
        } else {
            throw new InvalidKeySpecException(
                    "Only X.509 format for ML-DSA-65 and ML-DSA-87 is supported");
        }
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm");
        }
        return new OpenSslMlDsaPublicKey(raw, algorithm);
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
        if (encodedKeySpec.getFormat().equalsIgnoreCase("raw")) {
            byte[] raw = encodedKeySpec.getEncoded();
            if (raw.length != 32) {
                throw new InvalidKeySpecException("Invalid raw public key");
            }
            return new OpenSslMlDsaPrivateKey(raw, algorithm);
        }
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) {
            throw new InvalidKeySpecException("Encoding must be in PKCS#8 format");
        }

        byte[] encoded = encodedKeySpec.getEncoded();
        byte[] raw;
        MlDsaAlgorithm algorithm;
        if (ArrayUtils.startsWith(encoded, pkcs8PreambleMlDsa65)) {
            algorithm = MlDsaAlgorithm.ML_DSA_65;
            raw = Arrays.copyOfRange(encoded, pkcs8PreambleMlDsa65.length, encoded.length);
        } else if (ArrayUtils.startsWith(encoded, pkcs8PreambleMlDsa87)) {
            algorithm = MlDsaAlgorithm.ML_DSA_87;
            raw = Arrays.copyOfRange(encoded, pkcs8PreambleMlDsa87.length, encoded.length);
        } else {
            throw new InvalidKeySpecException("Unsupported PKCS8 key preamble");
        }
        if (raw.length != 32) {
            throw new InvalidKeySpecException("Invalid key");
        }
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm");
        }
        return new OpenSslMlDsaPrivateKey(raw, algorithm);
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
        if (!key.getAlgorithm().equals("ML-DSA")) {
            throw new InvalidKeySpecException("Key must be an ML-DSA key");
        }
        if (key instanceof OpenSslMlDsaPublicKey) {
            OpenSslMlDsaPublicKey conscryptKey = (OpenSslMlDsaPublicKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlDsaAlgorithm())) {
                throw new InvalidKeySpecException("Key algorithm mismatch");
            }
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new X509EncodedKeySpec(key.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslMlDsaPrivateKey) {
            OpenSslMlDsaPrivateKey conscryptKey = (OpenSslMlDsaPrivateKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlDsaAlgorithm())) {
                throw new InvalidKeySpecException("Key algorithm mismatch");
            }
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new PKCS8EncodedKeySpec(key.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getSeed(), keySpec);
            }
        }
        throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                + key.getClass().getName() + ", keySpec=" + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if ((key instanceof OpenSslMlDsaPublicKey) || (key instanceof OpenSslMlDsaPrivateKey)) {
            return key;
        }
        throw new InvalidKeyException(
                "Key must be OpenSslMlDsaPublicKey or OpenSslMlDsaPrivateKey");
    }
}
