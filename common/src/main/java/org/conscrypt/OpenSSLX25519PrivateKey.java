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

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class OpenSSLX25519PrivateKey implements OpenSSLX25519Key, PrivateKey {
    private static final long serialVersionUID = -3136201500221850916L;
    private static final byte[] PKCS8_PREAMBLE = new byte[]{
            0x30, 0x2e,                            // Sequence: 46 bytes
                0x02, 0x01, 0x00,                  // Integer: 0 (version)
                0x30, 0x05,                        // Sequence: 5 bytes
                    0x06, 0x03, 0x2b, 0x65, 0x6e,  // OID: 1.3.101.110 (X25519)
                0x04, 0x22, 0x04, 0x20,            // Octet string: 32 bytes
            // Key bytes follow directly
    };

    private byte[] uCoordinate;

    public OpenSSLX25519PrivateKey(EncodedKeySpec keySpec)
            throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if ("PKCS#8".equals(keySpec.getFormat())) {
            try {
                uCoordinate = NativeCrypto.EVP_raw_X25519_private_key(encoded);
            } catch (InvalidKeyException | ParsingException e) {
                throw new InvalidKeySpecException(e);
            }
        } else if ("raw".equalsIgnoreCase(keySpec.getFormat())) {
            uCoordinate = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in PKCS#8 or raw format");
        }
        if (uCoordinate.length != X25519_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid key size");
        }
    }

    public OpenSSLX25519PrivateKey(byte[] coordinateBytes) {
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return ArrayUtils.concat(PKCS8_PREAMBLE, uCoordinate);
    }

    @Override
    public byte[] getU() {
        if (uCoordinate == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return uCoordinate.clone();
    }

    @Override
    public void destroy() {
        if (uCoordinate != null) {
            Arrays.fill(uCoordinate, (byte) 0);
            uCoordinate = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return uCoordinate == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OpenSSLX25519PrivateKey)) return false;
        OpenSSLX25519PrivateKey that = (OpenSSLX25519PrivateKey) o;
        return Arrays.equals(uCoordinate, that.uCoordinate);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(uCoordinate);
    }
}
