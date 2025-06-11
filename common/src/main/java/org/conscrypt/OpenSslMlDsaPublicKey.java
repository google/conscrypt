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

import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

/** An OpenSSL ML-DSA public key. */
public class OpenSslMlDsaPublicKey implements PublicKey {
    private static final long serialVersionUID = 453861992373478445L;

    private final byte[] raw;
    private final MlDsaAlgorithm algorithm;

    private boolean isValidRawKey(byte[] rawKey, MlDsaAlgorithm algorithm) {
        return rawKey.length == algorithm.publicKeySize();
    }

    public OpenSslMlDsaPublicKey(EncodedKeySpec keySpec, MlDsaAlgorithm algorithm)
            throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (!"raw".equalsIgnoreCase(keySpec.getFormat())) {
            throw new InvalidKeySpecException("Encoding must be in raw format");
        }
        if (!isValidRawKey(encoded, algorithm)) {
            throw new InvalidKeySpecException("Invalid raw key");
        }
        this.raw = encoded;
        this.algorithm = algorithm;
    }

    public OpenSslMlDsaPublicKey(byte[] raw, MlDsaAlgorithm algorithm) {
        if (!isValidRawKey(raw, algorithm)) {
            throw new IllegalArgumentException("Invalid raw key");
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

        return algorithm.equals(that.algorithm) && Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Objects.hash(Arrays.hashCode(raw), algorithm);
    }
}
