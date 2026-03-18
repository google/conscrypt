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
import java.security.PublicKey;
import java.util.Arrays;

/** An ML-KEM public key. */
public class OpenSslMlKemPublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;

    private final byte[] raw;
    private final MlKemAlgorithm algorithm;

    public OpenSslMlKemPublicKey(byte[] raw, MlKemAlgorithm algorithm) {
        if (!algorithm.equals(MlKemAlgorithm.ML_KEM_768)
            && !algorithm.equals(MlKemAlgorithm.ML_KEM_1024)) {
            throw new IllegalArgumentException("Unsupported algorithm");
        }
        if (raw.length != algorithm.publicKeySize()) {
            throw new IllegalArgumentException("Invalid raw key of length " + raw.length);
        }
        this.raw = raw.clone();
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
        return "X.509";
    }

    private static byte[] getX509Preamble(MlKemAlgorithm algorithm) {
        switch (algorithm) {
            case ML_KEM_768:
                return OpenSslMlKemKeyFactory.x509PreambleMlKem768;
            case ML_KEM_1024:
                return OpenSslMlKemKeyFactory.x509PreambleMlKem1024;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    @Override
    public byte[] getEncoded() {
        return ArrayUtils.concat(getX509Preamble(algorithm), raw);
    }

    byte[] getRaw() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return raw.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslMlKemPublicKey)) {
            return false;
        }
        OpenSslMlKemPublicKey that = (OpenSslMlKemPublicKey) o;
        return Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(raw) ^ algorithm.hashCode();
    }

    private void readObject(ObjectInputStream in) {
        throw new UnsupportedOperationException("serialization not supported");
    }

    private void writeObject(ObjectOutputStream out) {
        throw new UnsupportedOperationException("serialization not supported");
    }
}
