/*
 * Copyright (C) 2026 The Android Open Source Project
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
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * OpenSSL Key Encapsulation Mechanism (KEM) SPI implementation for ML-KEM algorithms.
 */
@android.annotation.Hide // This class is not part of the Android public SDK API
@SuppressWarnings("NewApi")
@Internal
public final class OpenSslMlKem {
    private OpenSslMlKem() {}

    /** Generic ML-KEM implementation supporting all ML-KEM variants. */
    public static class MlKem implements KEMSpi {
        public MlKem() {}

        @Override
        public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                                                     AlgorithmParameterSpec spec,
                                                     SecureRandom secureRandom)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM");
            }
            OpenSslMlKemPublicKey key =
                    (OpenSslMlKemPublicKey) new OpenSslMlKemKeyFactory.MlKem().engineTranslateKey(
                            publicKey);
            if (key.getMlKemAlgorithm().equals(MlKemAlgorithm.ML_KEM_768)) {
                return new MlKem768Encapsulator(key.getRaw());
            } else if (key.getMlKemAlgorithm().equals(MlKemAlgorithm.ML_KEM_1024)) {
                return new MlKem1024Encapsulator(key.getRaw());
            }
            throw new InvalidKeyException("Unsupported ML-KEM key variant: "
                                          + key.getMlKemAlgorithm());
        }

        @Override
        public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
                                                     AlgorithmParameterSpec spec)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM");
            }
            OpenSslMlKemPrivateKey key =
                    (OpenSslMlKemPrivateKey) new OpenSslMlKemKeyFactory.MlKem().engineTranslateKey(
                            privateKey);
            if (key.getMlKemAlgorithm().equals(MlKemAlgorithm.ML_KEM_768)) {
                return new MlKem768Decapsulator(key.getSeed());
            } else if (key.getMlKemAlgorithm().equals(MlKemAlgorithm.ML_KEM_1024)) {
                return new MlKem1024Decapsulator(key.getSeed());
            }
            throw new InvalidKeyException("Unsupported ML-KEM key variant: "
                                          + key.getMlKemAlgorithm());
        }
    }

    /** ML-KEM-768 implementation. */
    public static class MlKem768 implements KEMSpi {
        static final int CIPHERTEXT_SIZE = 1088;
        static final int SECRET_SIZE = 32;

        public MlKem768() {}

        @Override
        public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                                                     AlgorithmParameterSpec spec,
                                                     SecureRandom secureRandom)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM-768");
            }
            OpenSslMlKemPublicKey key =
                    (OpenSslMlKemPublicKey) new OpenSslMlKemKeyFactory.MlKem768()
                            .engineTranslateKey(publicKey);
            return new MlKem768Encapsulator(key.getRaw());
        }

        @Override
        public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
                                                     AlgorithmParameterSpec spec)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM-768");
            }
            OpenSslMlKemPrivateKey key =
                    (OpenSslMlKemPrivateKey) new OpenSslMlKemKeyFactory.MlKem768()
                            .engineTranslateKey(privateKey);
            return new MlKem768Decapsulator(key.getSeed());
        }
    }

    /** ML-KEM-1024 implementation. */
    public static class MlKem1024 implements KEMSpi {
        static final int CIPHERTEXT_SIZE = 1568;
        static final int SECRET_SIZE = 32;

        public MlKem1024() {}

        @Override
        public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                                                     AlgorithmParameterSpec spec,
                                                     SecureRandom secureRandom)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM-1024");
            }
            OpenSslMlKemPublicKey key =
                    (OpenSslMlKemPublicKey) new OpenSslMlKemKeyFactory.MlKem1024()
                            .engineTranslateKey(publicKey);
            return new MlKem1024Encapsulator(key.getRaw());
        }

        @Override
        public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
                                                     AlgorithmParameterSpec spec)
                throws InvalidAlgorithmParameterException, InvalidKeyException {
            if (spec != null) {
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec not supported for ML-KEM-1024");
            }
            OpenSslMlKemPrivateKey key =
                    (OpenSslMlKemPrivateKey) new OpenSslMlKemKeyFactory.MlKem1024()
                            .engineTranslateKey(privateKey);
            return new MlKem1024Decapsulator(key.getSeed());
        }
    }

    private static final class MlKem768Encapsulator implements KEMSpi.EncapsulatorSpi {
        private final byte[] rawPublicKey;

        MlKem768Encapsulator(byte[] rawPublicKey) {
            this.rawPublicKey = rawPublicKey;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            Objects.requireNonNull(algorithm, "algorithm == null");
            checkKeyRange(from, to, MlKem768.SECRET_SIZE);

            byte[] outCiphertext = new byte[MlKem768.CIPHERTEXT_SIZE];
            byte[] outSharedSecret = new byte[MlKem768.SECRET_SIZE];
            NativeCrypto.MLKEM768_encap(rawPublicKey, outCiphertext, outSharedSecret);

            byte[] keyBytes = Arrays.copyOfRange(outSharedSecret, from, to);
            SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);
            return new KEM.Encapsulated(secretKey, outCiphertext, null);
        }

        @Override
        public int engineSecretSize() {
            return MlKem768.SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return MlKem768.CIPHERTEXT_SIZE;
        }
    }

    private static final class MlKem768Decapsulator implements KEMSpi.DecapsulatorSpi {
        private final byte[] seed;

        MlKem768Decapsulator(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            Objects.requireNonNull(encapsulation, "encapsulation == null");
            Objects.requireNonNull(algorithm, "algorithm == null");
            if (encapsulation.length != MlKem768.CIPHERTEXT_SIZE) {
                throw new DecapsulateException("Invalid encapsulation size: " + encapsulation.length
                                               + ", expected: " + MlKem768.CIPHERTEXT_SIZE);
            }
            checkKeyRange(from, to, MlKem768.SECRET_SIZE);

            byte[] outSharedSecret;
            try {
                outSharedSecret = NativeCrypto.MLKEM768_decap(encapsulation, seed);
            } catch (Exception e) {
                throw new DecapsulateException("Failed to decapsulate ML-KEM-768", e);
            }
            if (outSharedSecret == null || outSharedSecret.length != MlKem768.SECRET_SIZE) {
                throw new DecapsulateException("Decapsulation produced invalid shared secret");
            }

            byte[] keyBytes = Arrays.copyOfRange(outSharedSecret, from, to);
            return new SecretKeySpec(keyBytes, algorithm);
        }

        @Override
        public int engineSecretSize() {
            return MlKem768.SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return MlKem768.CIPHERTEXT_SIZE;
        }
    }

    private static final class MlKem1024Encapsulator implements KEMSpi.EncapsulatorSpi {
        private final byte[] rawPublicKey;

        MlKem1024Encapsulator(byte[] rawPublicKey) {
            this.rawPublicKey = rawPublicKey;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            Objects.requireNonNull(algorithm, "algorithm == null");
            checkKeyRange(from, to, MlKem1024.SECRET_SIZE);

            byte[] outCiphertext = new byte[MlKem1024.CIPHERTEXT_SIZE];
            byte[] outSharedSecret = new byte[MlKem1024.SECRET_SIZE];
            NativeCrypto.MLKEM1024_encap(rawPublicKey, outCiphertext, outSharedSecret);

            byte[] keyBytes = Arrays.copyOfRange(outSharedSecret, from, to);
            SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);
            return new KEM.Encapsulated(secretKey, outCiphertext, null);
        }

        @Override
        public int engineSecretSize() {
            return MlKem1024.SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return MlKem1024.CIPHERTEXT_SIZE;
        }
    }

    private static final class MlKem1024Decapsulator implements KEMSpi.DecapsulatorSpi {
        private final byte[] seed;

        MlKem1024Decapsulator(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            Objects.requireNonNull(encapsulation, "encapsulation == null");
            Objects.requireNonNull(algorithm, "algorithm == null");
            if (encapsulation.length != MlKem1024.CIPHERTEXT_SIZE) {
                throw new DecapsulateException("Invalid encapsulation size: " + encapsulation.length
                                               + ", expected: " + MlKem1024.CIPHERTEXT_SIZE);
            }
            checkKeyRange(from, to, MlKem1024.SECRET_SIZE);

            byte[] outSharedSecret;
            try {
                outSharedSecret = NativeCrypto.MLKEM1024_decap(encapsulation, seed);
            } catch (Exception e) {
                throw new DecapsulateException("Failed to decapsulate ML-KEM-1024", e);
            }
            if (outSharedSecret == null || outSharedSecret.length != MlKem1024.SECRET_SIZE) {
                throw new DecapsulateException("Decapsulation produced invalid shared secret");
            }

            byte[] keyBytes = Arrays.copyOfRange(outSharedSecret, from, to);
            return new SecretKeySpec(keyBytes, algorithm);
        }

        @Override
        public int engineSecretSize() {
            return MlKem1024.SECRET_SIZE;
        }

        @Override
        public int engineEncapsulationSize() {
            return MlKem1024.CIPHERTEXT_SIZE;
        }
    }

    private static void checkKeyRange(int from, int to, int secretSize) {
        if (from < 0 || from > to || to > secretSize) {
            throw new IndexOutOfBoundsException("Invalid range: from=" + from + ", to=" + to
                                                + ", secretSize=" + secretSize);
        }
    }
}
