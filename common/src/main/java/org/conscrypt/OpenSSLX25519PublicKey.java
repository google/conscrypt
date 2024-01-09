/*
 * Copyright 2022 The Android Open Source Project
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

public class OpenSSLX25519PublicKey implements OpenSSLX25519Key, PublicKey {
    private static final long serialVersionUID = 453861992373478445L;

    private static final byte[] X509_PREAMBLE = new byte[] {
            0x30, 0x2a,                       // Sequence: 42 bytes
                0x30, 0x05,                   // Sequence: 5 bytes
                0x06, 0x03, 0x2b, 0x65, 0x6e, // OID: 1.3.101.110 (X25519)
            0x03, 0x21, 0x00,                 // Bit string: 256 bits
            // Key bytes follow directly
    };

    private final byte[] uCoordinate;

    public OpenSSLX25519PublicKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if ("X.509".equals(keySpec.getFormat())) {
            if (!ArrayUtils.startsWith(encoded, X509_PREAMBLE)) {
                throw new InvalidKeySpecException("Invalid format");
            }
            int totalLength = X509_PREAMBLE.length + X25519_KEY_SIZE_BYTES;
            if (encoded.length < totalLength) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            uCoordinate = Arrays.copyOfRange(encoded, X509_PREAMBLE.length, totalLength);
        } else if ("raw".equalsIgnoreCase(keySpec.getFormat())) {
            if (encoded.length != X25519_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            uCoordinate = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in X.509 or raw format");
        }
    }

    public OpenSSLX25519PublicKey(byte[] coordinateBytes) {
        if (coordinateBytes.length != X25519_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        uCoordinate = coordinateBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        return ArrayUtils.concat(X509_PREAMBLE, uCoordinate);
    }

    @Override
    public byte[] getU() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return uCoordinate.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) return true;
        if (!(o instanceof OpenSSLX25519PublicKey)) return false;
        OpenSSLX25519PublicKey that = (OpenSSLX25519PublicKey) o;
        return Arrays.equals(uCoordinate, that.uCoordinate);
    }

    @Override
    public int hashCode() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(uCoordinate);
    }
}
