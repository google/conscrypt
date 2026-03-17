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

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * An implementation of {@link KeyPairGenerator} for ML-KEM keys which uses BoringSSL to perform all
 * the operations. It supports algorithms "ML-KEM", "ML-KEM-768" and "ML-KEM-1024". "ML-DSA" uses
 * ML-DSA-768.
 */
@Internal
public class OpenSslMlKemKeyPairGenerator extends KeyPairGenerator {
    private OpenSslMlKemKeyPairGenerator(String algorithm) {
        super(algorithm);
    }

    /** ML-KEM-768 */
    public static class MlKem768 extends OpenSslMlKemKeyPairGenerator {
        public MlKem768() {
            super("ML-KEM-768");
        }

        MlKem768(String algorithm) {
            super(algorithm);
        }

        @Override
        public KeyPair generateKeyPair() {
            byte[] privateKeyBytes = new byte[64];
            NativeCrypto.RAND_bytes(privateKeyBytes);
            byte[] publicKeyBytes = NativeCrypto.MLKEM768_public_key_from_seed(privateKeyBytes);
            return new KeyPair(
                    new OpenSslMlKemPublicKey(publicKeyBytes, MlKemAlgorithm.ML_KEM_768),
                    new OpenSslMlKemPrivateKey(privateKeyBytes, MlKemAlgorithm.ML_KEM_768));
        }
    }

    /** ML-KEM uses ML-KEM-768. */
    public static class MlKem extends MlKem768 {
        public MlKem() {
            super("ML-KEM");
        }
    }

    /** ML-KEM-1024 */
    public static final class MlKem1024 extends OpenSslMlKemKeyPairGenerator {
        public MlKem1024() {
            super("ML-KEM-1024");
        }

        @Override
        public KeyPair generateKeyPair() {
            byte[] privateKeyBytes = new byte[OpenSslMlKemPrivateKey.PRIVATE_KEY_SIZE_BYTES];
            NativeCrypto.RAND_bytes(privateKeyBytes);
            byte[] publicKeyBytes = NativeCrypto.MLKEM1024_public_key_from_seed(privateKeyBytes);
            return new KeyPair(
                    new OpenSslMlKemPublicKey(publicKeyBytes, MlKemAlgorithm.ML_KEM_1024),
                    new OpenSslMlKemPrivateKey(privateKeyBytes, MlKemAlgorithm.ML_KEM_1024));
        }
    }

    @Override
    public void initialize(int bits) throws InvalidParameterException {
        if (bits != -1) {
            throw new InvalidParameterException("ML-DSA only supports -1 for bits");
        }
    }
}
