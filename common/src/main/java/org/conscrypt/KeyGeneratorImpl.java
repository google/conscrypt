/*
 * Copyright (C) 2017 The Android Open Source Project
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
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of {@link javax.crypto.KeyGenerator} suitable for use with other Conscrypt
 * algorithms.
 */
@Internal
public abstract class KeyGeneratorImpl extends KeyGeneratorSpi {
    private final String algorithm;
    protected SecureRandom secureRandom;
    private int keySizeBits;

    private KeyGeneratorImpl(String algorithm, int defaultKeySizeBits) {
        this.algorithm = algorithm;
        this.keySizeBits = defaultKeySizeBits;
    }

    protected void checkKeySize(int keySize) {
        if (keySize <= 0) {
            throw new InvalidParameterException("Key size must be positive");
        }
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("No params provided");
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Unknown param type: " + params.getClass().getName());
        }
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        checkKeySize(keySize);
        this.keySizeBits = keySize;
        this.secureRandom = secureRandom;
    }

    protected byte[] doKeyGeneration(int keyBytes) {
        byte[] keyData = new byte[keyBytes];
        secureRandom.nextBytes(keyData);
        return keyData;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }

        return new SecretKeySpec(doKeyGeneration((keySizeBits + 7) / 8), algorithm);
    }

    // For HMAC, RFC 2104 recommends using the hash's output length as the key length
    public static final class HmacMD5 extends KeyGeneratorImpl {
        public HmacMD5() {
            super("HmacMD5", 128);
        }
    }

    public static final class HmacSHA1 extends KeyGeneratorImpl {
        public HmacSHA1() {
            super("HmacSHA1", 160);
        }
    }

    public static final class HmacSHA224 extends KeyGeneratorImpl {
        public HmacSHA224() {
            super("HmacSHA224", 224);
        }
    }

    public static final class HmacSHA256 extends KeyGeneratorImpl {
        public HmacSHA256() {
            super("HmacSHA256", 256);
        }
    }

    public static final class HmacSHA384 extends KeyGeneratorImpl {
        public HmacSHA384() {
            super("HmacSHA384", 384);
        }
    }

    public static final class HmacSHA512 extends KeyGeneratorImpl {
        public HmacSHA512() {
            super("HmacSHA512", 512);
        }
    }

    public static final class DESEDE extends KeyGeneratorImpl {
        public DESEDE() {
            super("DESEDE", 192);
        }

        @Override
        protected void checkKeySize(int keySize) {
            if ((keySize != 112) && (keySize != 168)) {
                throw new InvalidParameterException("Key size must be either 112 or 168 bits");
            }
        }

        @Override
        protected byte[] doKeyGeneration(int keyBytes) {
            byte[] keyData = new byte[DESedeKeySpec.DES_EDE_KEY_LEN];
            secureRandom.nextBytes(keyData);
            // Set the parity bit for each byte
            for (int i = 0; i < keyData.length; i++) {
                if (Integer.bitCount(keyData[i]) % 2 == 0) {
                    keyData[i] = (byte) (keyData[i] ^ 1);
                }
            }
            if (keyBytes == 14) {
                // The user requested an A-B-A key
                System.arraycopy(keyData, 0, keyData, 16, 8);
            }
            return keyData;
        }
    }

    public static final class AES extends KeyGeneratorImpl {
        public AES() {
            super("AES", 128);
        }

        @Override
        protected void checkKeySize(int keySize) {
            if ((keySize != 128) && (keySize != 192) && (keySize != 256)) {
                throw new InvalidParameterException(
                        "Key size must be either 128, 192, or 256 bits");
            }
        }
    }

    public static final class ChaCha20 extends KeyGeneratorImpl {
        public ChaCha20() {
            super("ChaCha20", 256);
        }

        @Override
        protected void checkKeySize(int keySize) {
            if (keySize != 256) {
                throw new InvalidParameterException("Key size must be 256 bits");
            }
        }
    }

    public static final class ARC4 extends KeyGeneratorImpl {
        public ARC4() {
            super("ARC4", 128);
        }

        @Override
        protected void checkKeySize(int keySize) {
            if (keySize < 40 || 2048 < keySize) {
                throw new InvalidParameterException("Key size must be between 40 and 2048 bits");
            }
        }
    }
}
