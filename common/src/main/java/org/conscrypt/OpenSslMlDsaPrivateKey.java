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

import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An OpenSSL ML-DSA private key. */
public class OpenSslMlDsaPrivateKey implements PrivateKey {
    private byte[] seed;

    public OpenSslMlDsaPrivateKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if ("raw".equalsIgnoreCase(keySpec.getFormat())) {
            seed = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in raw format");
        }
    }

    public OpenSslMlDsaPrivateKey(byte[] seed) {
        this.seed = seed.clone();
    }

    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("getFormat() not yet supported");
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("getEncoded() not yet supported");
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
        if (!(o instanceof OpenSslMlDsaPrivateKey)) {
            return false;
        }
        OpenSslMlDsaPrivateKey that = (OpenSslMlDsaPrivateKey) o;
        return Arrays.equals(seed, that.seed);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(seed);
    }
}
