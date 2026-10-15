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

package javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

@SuppressWarnings({"unused", "DoNotCallSuggester"})
public final class KEM {
    public static final class Encapsulated {
        public Encapsulated(SecretKey key, byte[] encapsulation, byte[] params) {
            throw new UnsupportedOperationException("Stub!");
        }

        public SecretKey key() {
            throw new UnsupportedOperationException("Stub!");
        }

        public byte[] encapsulation() {
            throw new UnsupportedOperationException("Stub!");
        }

        public byte[] params() {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    public static final class Encapsulator {
        private Encapsulator() {}

        public String providerName() {
            throw new UnsupportedOperationException("Stub!");
        }

        public Encapsulated encapsulate() {
            throw new UnsupportedOperationException("Stub!");
        }

        public Encapsulated encapsulate(int from, int to, String algorithm) {
            throw new UnsupportedOperationException("Stub!");
        }

        public int secretSize() {
            throw new UnsupportedOperationException("Stub!");
        }

        public int encapsulationSize() {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    public static final class Decapsulator {
        private Decapsulator() {}

        public String providerName() {
            throw new UnsupportedOperationException("Stub!");
        }

        public SecretKey decapsulate(byte[] encapsulation) throws DecapsulateException {
            throw new UnsupportedOperationException("Stub!");
        }

        public SecretKey decapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            throw new UnsupportedOperationException("Stub!");
        }

        public int secretSize() {
            throw new UnsupportedOperationException("Stub!");
        }

        public int encapsulationSize() {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    private KEM() {}

    public static KEM getInstance(String algorithm) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KEM getInstance(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Stub!");
    }

    public static KEM getInstance(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        throw new UnsupportedOperationException("Stub!");
    }

    public String getAlgorithm() {
        throw new UnsupportedOperationException("Stub!");
    }

    public Provider getProvider() {
        throw new UnsupportedOperationException("Stub!");
    }

    public Encapsulator newEncapsulator(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("Stub!");
    }

    public Encapsulator newEncapsulator(PublicKey publicKey, SecureRandom secureRandom)
            throws InvalidKeyException {
        throw new UnsupportedOperationException("Stub!");
    }

    public Encapsulator newEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                                        SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        throw new UnsupportedOperationException("Stub!");
    }

    public Decapsulator newDecapsulator(PrivateKey privateKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("Stub!");
    }

    public Decapsulator newDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        throw new UnsupportedOperationException("Stub!");
    }
}
