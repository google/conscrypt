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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An OpenSSL ML-DSA public key. */
public class OpenSslMlDsaPublicKey implements PublicKey {
    private static final long serialVersionUID = 453861992373478445L;

    private byte[] raw;
    private transient MlDsaAlgorithm algorithm;

    private static boolean isValid(byte[] raw, MlDsaAlgorithm algorithm) {
        return raw.length == algorithm.publicKeySize();
    }

    private static MlDsaAlgorithm getAlgorithmFromRaw(byte[] raw) {
        if (raw.length == MlDsaAlgorithm.ML_DSA_65.publicKeySize()) {
            return MlDsaAlgorithm.ML_DSA_65;
        }
        if (raw.length == MlDsaAlgorithm.ML_DSA_87.publicKeySize()) {
            return MlDsaAlgorithm.ML_DSA_87;
        }
        throw new IllegalArgumentException("Invalid raw key of length " + raw.length);
    }

    public OpenSslMlDsaPublicKey(EncodedKeySpec keySpec, MlDsaAlgorithm algorithm)
            throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (!"raw".equalsIgnoreCase(keySpec.getFormat())) {
            throw new InvalidKeySpecException("Encoding must be in raw format");
        }
        if (!isValid(encoded, algorithm)) {
            throw new InvalidKeySpecException("Invalid key of length " + encoded.length);
        }
        this.raw = encoded;
        this.algorithm = algorithm;
    }

    public OpenSslMlDsaPublicKey(byte[] raw, MlDsaAlgorithm algorithm) {
        if (!isValid(raw, algorithm)) {
            throw new IllegalArgumentException("Invalid key of length " + raw.length);
        }
        this.raw = raw.clone();
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    public MlDsaAlgorithm getMlDsaAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("getFormat() not yet supported");
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("getEncoded() not yet supported");
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
        if (!(o instanceof OpenSslMlDsaPublicKey)) {
            return false;
        }
        OpenSslMlDsaPublicKey that = (OpenSslMlDsaPublicKey) o;

        // different algorithms have different raw key lengths, so we only need to compare the raw
        // key.
        return Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(raw);
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject(); // reads "this.raw"
        this.algorithm = getAlgorithmFromRaw(this.raw);
        if (!isValid(this.raw, this.algorithm)) {
            throw new IOException("Invalid key");
        }
    }
}
