/*
 * Copyright 2025 The Android Open Source Project
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

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;

/** An ML-KEM private key. */
public class OpenSslMlKemPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;

    static final int PRIVATE_KEY_SIZE_BYTES = 64;

    private byte[] seed;
    private final MlKemAlgorithm algorithm;

    public OpenSslMlKemPrivateKey(byte[] seed, MlKemAlgorithm algorithm) {
        if (seed.length != PRIVATE_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.seed = seed.clone();
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
    }

    MlKemAlgorithm getMlKemAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    private static byte[] getPkcs8Preamble(MlKemAlgorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768:
                return OpenSslMlKemKeyFactory.pkcs8PreambleMlKem768;
            case ML_KEM_1024:
                return OpenSslMlKemKeyFactory.pkcs8PreambleMlKem1024;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    @Override
    public byte[] getEncoded() {
        return ArrayUtils.concat(getPkcs8Preamble(algorithm), seed);
    }

    byte[] getSeed() {
        if (seed == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return seed.clone();
    }

    @Override
    public void destroy() {
        if (seed != null) {
            Arrays.fill(seed, (byte) 0);
            seed = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return seed == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslMlKemPrivateKey)) {
            return false;
        }
        OpenSslMlKemPrivateKey that = (OpenSslMlKemPrivateKey) o;
        return MessageDigest.isEqual(seed, that.seed);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(seed) ^ algorithm.hashCode();
    }

    private void readObject(ObjectInputStream in) {
        throw new UnsupportedOperationException("serialization not supported");
    }

    private void writeObject(ObjectOutputStream out) {
        throw new UnsupportedOperationException("serialization not supported");
    }
}
