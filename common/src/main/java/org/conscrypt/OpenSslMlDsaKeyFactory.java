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
            super(null);
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

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (algorithm == null) {
            throw new InvalidKeySpecException("ML-DSA key factory doesn't support public key"
                    + " generation from raw keys. Use ML-DSA-65 or ML-DSA-87 instead.");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSslMlDsaPublicKey((EncodedKeySpec) keySpec, algorithm);
        }
        throw new InvalidKeySpecException(
                "Currently only EncodedKeySpec is supported; was " + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (algorithm == null) {
            throw new InvalidKeySpecException("ML-DSA key factory doesn't support private key"
                    + " generation from raw keys. Use ML-DSA-65 or ML-DSA-87 instead.");
        }
        if (keySpec instanceof EncodedKeySpec) {
            return new OpenSslMlDsaPrivateKey((EncodedKeySpec) keySpec, algorithm);
        }
        throw new InvalidKeySpecException(
                "Currently only EncodedKeySpec is supported; was " + keySpec.getClass().getName());
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
                throw new UnsupportedOperationException(
                        "X509EncodedKeySpec is currently not supported");
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslMlDsaPrivateKey) {
            OpenSslMlDsaPrivateKey conscryptKey = (OpenSslMlDsaPrivateKey) key;
            if (!supportsAlgorithm(conscryptKey.getMlDsaAlgorithm())) {
                throw new InvalidKeySpecException("Key algorithm mismatch");
            }
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                throw new UnsupportedOperationException(
                        "PKCS8EncodedKeySpec is currently not supported");
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return makeRawKeySpec(conscryptKey.getSeed(), keySpec);
            }
        }
        throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                + key.getClass().getName() + ", keySpec=" + keySpec.getName());
    }

    private <T extends KeySpec> T makeRawKeySpec(byte[] bytes, Class<T> keySpecClass)
            throws InvalidKeySpecException {
        try {
            Constructor<T> constructor = keySpecClass.getConstructor(byte[].class);
            T instance = constructor.newInstance((Object) bytes);
            EncodedKeySpec spec = (EncodedKeySpec) instance;
            if (!spec.getFormat().equalsIgnoreCase("raw")) {
                throw new InvalidKeySpecException("EncodedKeySpec class must be raw format");
            }
            return instance;
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException
                | IllegalAccessException e) {
            throw new InvalidKeySpecException(
                    "Can't process KeySpec class " + keySpecClass.getName(), e);
        }
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
