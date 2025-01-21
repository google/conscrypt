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

/** An OpenSSL EdDSA public key. */
public class OpenSslEdDsaPublicKey implements PublicKey {
    private static final long serialVersionUID = 453861992373478445L;

    private static final byte[] X509_PREAMBLE = new byte[] {
            0x30, 0x2a, // Sequence: 42 bytes
            0x30, 0x05, // Sequence: 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID: 1.3.101.112 (id-EdDSA)
            0x03, 0x21, 0x00, // Bit string: 256 bits
            // Key bytes follow directly
    };

    static final int ED25519_PUBLIC_KEY_SIZE_BYTES = 32;

    private final byte[] publicKeyBytes;

    public OpenSslEdDsaPublicKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (keySpec.getFormat().equals("X.509")) {
            if (!ArrayUtils.startsWith(encoded, X509_PREAMBLE)) {
                throw new InvalidKeySpecException("Invalid format");
            }
            int totalLength = X509_PREAMBLE.length + ED25519_PUBLIC_KEY_SIZE_BYTES;
            if (encoded.length < totalLength) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            publicKeyBytes = Arrays.copyOfRange(encoded, X509_PREAMBLE.length, totalLength);
        } else if (keySpec.getFormat().equalsIgnoreCase("raw")) {
            if (encoded.length != ED25519_PUBLIC_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            publicKeyBytes = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in X.509 or raw format");
        }
    }

    public OpenSslEdDsaPublicKey(byte[] coordinateBytes) {
        if (coordinateBytes.length != ED25519_PUBLIC_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        publicKeyBytes = coordinateBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (publicKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }

        return ArrayUtils.concat(X509_PREAMBLE, publicKeyBytes);
    }

    byte[] getRaw() {
        if (publicKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return publicKeyBytes.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (publicKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslEdDsaPublicKey)) {
            return false;
        }
        OpenSslEdDsaPublicKey that = (OpenSslEdDsaPublicKey) o;
        return Arrays.equals(publicKeyBytes, that.publicKeyBytes);
    }

    @Override
    public int hashCode() {
        if (publicKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(publicKeyBytes);
    }
}
