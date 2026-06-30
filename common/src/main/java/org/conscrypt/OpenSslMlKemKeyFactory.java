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

/** An implementation of a {@link KeyFactorySpi} for ML-KEM keys based on BoringSSL. */
@Internal
public abstract class OpenSslMlKemKeyFactory extends KeyFactorySpi {
    // X.509 format preamble for ML-KEM-768 from RFC 9935.
    static final byte[] x509PreambleMlKem768 = new byte[] {
            (byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xb2, (byte) 0x30, (byte) 0x0b,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
            (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04, (byte) 0x02, (byte) 0x03,
            (byte) 0x82, (byte) 0x04, (byte) 0xa1, (byte) 0x00};

    // X.509 format preamble for ML-KEM-1024 from RFC 9935.
    static final byte[] x509PreambleMlKem1024 = new byte[] {
            (byte) 0x30, (byte) 0x82, (byte) 0x06, (byte) 0x32, (byte) 0x30, (byte) 0x0b,
            (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
            (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x03,
            (byte) 0x82, (byte) 0x06, (byte) 0x21, (byte) 0x00};

    // PKCS#8 format preamble (seed format) for ML-KEM-768 from RFC 9935.
    static final byte[] pkcs8PreambleMlKem768 = new byte[] {
            (byte) 0x30, (byte) 0x54, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30,
            (byte) 0x0b, (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
            (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04, (byte) 0x02,
            (byte) 0x04, (byte) 0x42, (byte) 0x80, (byte) 0x40};

    // PKCS#8 format preamble (seed format) for ML-KEM-1024 from RFC 9935.
    static final byte[] pkcs8PreambleMlKem1024 = new byte[] {
            (byte) 0x30, (byte) 0x54, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30,
            (byte) 0x0b, (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
            (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04, (byte) 0x03,
            (byte) 0x04, (byte) 0x42, (byte) 0x80, (byte) 0x40};

    private final MlKemAlgorithm defaultAlgorithm;

    private OpenSslMlKemKeyFactory(MlKemAlgorithm defaultAlgorithm) {
        this.defaultAlgorithm = defaultAlgorithm;
    }

    abstract boolean supportsAlgorithm(MlKemAlgorithm algorithm);

    /** ML-KEM */
    public static class MlKem extends OpenSslMlKemKeyFactory {
        public MlKem() {
            super(MlKemAlgorithm.ML_KEM_768);
        }

        @Override
        boolean supportsAlgorithm(MlKemAlgorithm algorithm) {
            return algorithm.equals(MlKemAlgorithm.ML_KEM_768)
                    || algorithm.equals(MlKemAlgorithm.ML_KEM_1024);
        }
    }

    /** ML-KEM-768 */
    public static class MlKem768 extends OpenSslMlKemKeyFactory {
        public MlKem768() {
            super(MlKemAlgorithm.ML_KEM_768);
        }

        @Override
        boolean supportsAlgorithm(MlKemAlgorithm algorithm) {
            return algorithm.equals(MlKemAlgorithm.ML_KEM_768);
        }
    }

    /** ML-KEM-1024 */
    public static class MlKem1024 extends OpenSslMlKemKeyFactory {
        public MlKem1024() {
            super(MlKemAlgorithm.ML_KEM_1024);
        }

        @Override
        boolean supportsAlgorithm(MlKemAlgorithm algorithm) {
            return algorithm.equals(MlKemAlgorithm.ML_KEM_1024);
        }
    }

    private OpenSslMlKemPublicKey makePublicKeyFromRaw(byte[] raw, MlKemAlgorithm algorithm)
            throws InvalidKeySpecException {
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        if (raw.length != algorithm.publicKeySize()) {
            throw new InvalidKeySpecException("Invalid raw public key length: " + raw.length
                                              + " != " + algorithm.publicKeySize());
        }
        try {
            return new OpenSslMlKemPublicKey(raw, algorithm);
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
        if (encodedKeySpec.getFormat().equalsIgnoreCase("raw")) {
            byte[] raw = encodedKeySpec.getEncoded();
            return makePublicKeyFromRaw(raw, defaultAlgorithm);
        }
        if (!encodedKeySpec.getFormat().equals("X.509")) {
            throw new InvalidKeySpecException("Encoding must be in X.509 format");
        }
        byte[] encoded = encodedKeySpec.getEncoded();
        if (ArrayUtils.startsWith(encoded, x509PreambleMlKem768)) {
            byte[] raw = Arrays.copyOfRange(encoded, x509PreambleMlKem768.length, encoded.length);
            return makePublicKeyFromRaw(raw, MlKemAlgorithm.ML_KEM_768);
        } else if (ArrayUtils.startsWith(encoded, x509PreambleMlKem1024)) {
            byte[] raw = Arrays.copyOfRange(encoded, x509PreambleMlKem1024.length, encoded.length);
            return makePublicKeyFromRaw(raw, MlKemAlgorithm.ML_KEM_1024);
        } else {
            throw new InvalidKeySpecException(
                    "Only X.509 format for ML-KEM-768 and ML-KEM-1024 is supported");
        }
    }

    private OpenSslMlKemPrivateKey makePrivateKeyFromSeed(byte[] seed, MlKemAlgorithm algorithm)
            throws InvalidKeySpecException {
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        if (seed.length != OpenSslMlKemPrivateKey.PRIVATE_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid raw private key");
        }
        try {
            return new OpenSslMlKemPrivateKey(seed, algorithm);
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
        if (encodedKeySpec.getFormat().equalsIgnoreCase("raw")) {
            byte[] raw = encodedKeySpec.getEncoded();
            return makePrivateKeyFromSeed(raw, defaultAlgorithm);
        }
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) {
            throw new InvalidKeySpecException("Encoding must be in PKCS#8 format");
        }
        byte[] encoded = encodedKeySpec.getEncoded();
        if (ArrayUtils.startsWith(encoded, pkcs8PreambleMlKem768)) {
            byte[] seed = Arrays.copyOfRange(encoded, pkcs8PreambleMlKem768.length, encoded.length);
            return makePrivateKeyFromSeed(seed, MlKemAlgorithm.ML_KEM_768);
        } else if (ArrayUtils.startsWith(encoded, pkcs8PreambleMlKem1024)) {
            byte[] seed =
                    Arrays.copyOfRange(encoded, pkcs8PreambleMlKem1024.length, encoded.length);
            return makePrivateKeyFromSeed(seed, MlKemAlgorithm.ML_KEM_1024);
        } else {
            throw new InvalidKeySpecException(
                    "Only PKCS#8 format for ML-KEM-768 and ML-KEM-1024 is supported");
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
        if (!key.getAlgorithm().equals("ML-KEM")) {
            throw new InvalidKeySpecException("Key must be an ML-KEM key");
        }
        if (key instanceof OpenSslMlKemPublicKey) {
            OpenSslMlKemPublicKey conscryptKey = (OpenSslMlKemPublicKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlKemAlgorithm())) {
                throw new InvalidKeySpecException("Key algorithm mismatch");
            }
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                T result = (T) new X509EncodedKeySpec(key.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslMlKemPrivateKey) {
            OpenSslMlKemPrivateKey conscryptKey = (OpenSslMlKemPrivateKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlKemAlgorithm())) {
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
                                          + key.getClass().getName()
                                          + ", keySpec=" + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if ((key instanceof OpenSslMlKemPublicKey)) {
            OpenSslMlKemPublicKey conscryptKey = (OpenSslMlKemPublicKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlKemAlgorithm())) {
                throw new InvalidKeyException("Key algorithm mismatch");
            }
            return conscryptKey;
        } else if (key instanceof OpenSslMlKemPrivateKey) {
            OpenSslMlKemPrivateKey conscryptKey = (OpenSslMlKemPrivateKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlKemAlgorithm())) {
                throw new InvalidKeyException("Key algorithm mismatch");
            }
            return key;
        } else if ((key instanceof PrivateKey) && key.getFormat().equals("PKCS#8")) {
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
            throw new InvalidKeyException("Unable to translate key into ML-KEM key");
        }
    }
}
