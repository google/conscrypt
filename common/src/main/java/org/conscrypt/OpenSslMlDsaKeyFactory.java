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
    private final MlDsaAlgorithm defaultAlgorithm;

    private OpenSslMlDsaKeyFactory(MlDsaAlgorithm defaultAlgorithm) {
        this.defaultAlgorithm = defaultAlgorithm;
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

    private OpenSslMlDsaPublicKey makePublicKeyFromRaw(byte[] raw, MlDsaAlgorithm algorithm)
            throws InvalidKeySpecException {
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        if (raw.length != algorithm.publicKeySize()) {
            throw new InvalidKeySpecException("Invalid raw public key");
        }
        try {
            return new OpenSslMlDsaPublicKey(raw, algorithm);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid raw public key", e);
        }
    }

    static MlDsaAlgorithm getMlDsaAlgorithm(OpenSSLKey key) {
        int keyType = NativeCrypto.EVP_PKEY_type(key.getNativeRef());
        if (keyType == NativeConstants.EVP_PKEY_ML_DSA_65) {
            return MlDsaAlgorithm.ML_DSA_65;
        } else if (keyType == NativeConstants.EVP_PKEY_ML_DSA_87) {
            return MlDsaAlgorithm.ML_DSA_87;
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }
    }

    static int getPKeyType(MlDsaAlgorithm algorithm) {
        if (algorithm == MlDsaAlgorithm.ML_DSA_65) {
            return NativeConstants.EVP_PKEY_ML_DSA_65;
        } else if (algorithm == MlDsaAlgorithm.ML_DSA_87) {
            return NativeConstants.EVP_PKEY_ML_DSA_87;
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    private OpenSslMlDsaPublicKey makePublicKey(OpenSSLKey key) throws InvalidKeySpecException {
        MlDsaAlgorithm algorithm = getMlDsaAlgorithm(key);
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        try {
            return new OpenSslMlDsaPublicKey(key, algorithm);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid public key", e);
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
        try {
            OpenSSLKey key =
                    new OpenSSLKey(NativeCrypto.EVP_PKEY_from_subject_public_key_info(encoded,
                            new int[] {NativeConstants.EVP_PKEY_ML_DSA_65,
                                    NativeConstants.EVP_PKEY_ML_DSA_87}));
            return makePublicKey(key);
        } catch (OpenSSLX509CertificateFactory.ParsingException e) {
            throw new InvalidKeySpecException(
                "Unable to parse key. Only ML-DSA-65 and ML-DSA-87 are currently supported.", e);
        }
    }

    private OpenSslMlDsaPrivateKey makePrivateKeyFromSeed(byte[] seed, MlDsaAlgorithm algorithm)
            throws InvalidKeySpecException {
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        if (seed.length != 32) {
            throw new InvalidKeySpecException("Invalid raw private key");
        }
        try {
            return new OpenSslMlDsaPrivateKey(seed, algorithm);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid raw private key", e);
        }
    }

    private OpenSslMlDsaPrivateKey makePrivateKey(OpenSSLKey key) throws InvalidKeySpecException {
        MlDsaAlgorithm algorithm = getMlDsaAlgorithm(key);
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeySpecException("Unsupported algorithm: " + algorithm);
        }
        try {
            return new OpenSslMlDsaPrivateKey(key, algorithm);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid private key", e);
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
        try {
            OpenSSLKey key = new OpenSSLKey(NativeCrypto.EVP_PKEY_from_private_key_info(encoded,
                    new int[] {NativeConstants.EVP_PKEY_ML_DSA_65,
                            NativeConstants.EVP_PKEY_ML_DSA_87}));
            return makePrivateKey(key);
        } catch (OpenSSLX509CertificateFactory.ParsingException e) {
            if (encoded.length > 1000) {
                // Key is large, so it seems that it is not in the "seed format".
                throw new InvalidKeySpecException(
                    "Unable to parse key. Please use ML-DSA seed format as specified and recommended"
                    + " in RFC 9881.", e);
            }
            throw new InvalidKeySpecException(
                "Unable to parse key. Only ML-DSA-65 and ML-DSA-87 are currently supported.", e);
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
        if ((key instanceof OpenSslMlDsaPublicKey)) {
            OpenSslMlDsaPublicKey conscryptKey = (OpenSslMlDsaPublicKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlDsaAlgorithm())) {
                throw new InvalidKeyException("Key algorithm mismatch");
            }
            return conscryptKey;
        } else if (key instanceof OpenSslMlDsaPrivateKey) {
            OpenSslMlDsaPrivateKey conscryptKey = (OpenSslMlDsaPrivateKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlDsaAlgorithm())) {
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
            throw new InvalidKeyException("Unable to translate key into ML-DSA key");
        }
    }
}
