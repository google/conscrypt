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

/** An OpenSSL EdDSA private key. */
public class OpenSslEdDsaPrivateKey implements PrivateKey {
    private static final long serialVersionUID = -3136201500221850916L;
    private static final byte[] pkcs8Preamble = new byte[] {
            0x30, 0x2e, // Sequence: 46 bytes
            0x02, 0x01, 0x00, // Integer: 0 (version)
            0x30, 0x05, // Sequence: 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID: 1.3.101.112 (EdDSA)
            0x04, 0x22, 0x04, 0x20, // Octet string: 32 bytes
            // Key bytes follow directly
    };

    // BoringSSL uses a 64-byte private key. But this key here is only
    // the 32-byte seed, as defined in RFC 8032.
    static final int ED25519_PRIVATE_KEY_SIZE_BYTES = 32;

    private byte[] privateKeyBytes;

    public OpenSslEdDsaPrivateKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (keySpec.getFormat().equals("PKCS#8")) {
            byte[] preamble = Arrays.copyOf(encoded, pkcs8Preamble.length);
            if (!Arrays.equals(preamble, pkcs8Preamble)) {
                throw new InvalidKeySpecException("Invalid EdDSA PKCS8 key preamble");
            }
            privateKeyBytes = Arrays.copyOfRange(encoded, pkcs8Preamble.length, encoded.length);
        } else if (keySpec.getFormat().equalsIgnoreCase("raw")) {
            privateKeyBytes = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in PKCS#8 or raw format");
        }
        if (privateKeyBytes.length != ED25519_PRIVATE_KEY_SIZE_BYTES) {
            throw new InvalidKeySpecException("Invalid key size");
        }
    }

    public OpenSslEdDsaPrivateKey(byte[] privateKeyBytes) {
        if (privateKeyBytes.length != ED25519_PRIVATE_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.privateKeyBytes = privateKeyBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (privateKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return ArrayUtils.concat(pkcs8Preamble, privateKeyBytes);
    }

    byte[] getRaw() {
        if (privateKeyBytes == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return privateKeyBytes.clone();
    }

    @Override
    public void destroy() {
        if (privateKeyBytes != null) {
            Arrays.fill(privateKeyBytes, (byte) 0);
            privateKeyBytes = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return privateKeyBytes == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof OpenSslEdDsaPrivateKey)) {
            return false;
        }
        OpenSslEdDsaPrivateKey that = (OpenSslEdDsaPrivateKey) o;
        return Arrays.equals(privateKeyBytes, that.privateKeyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(privateKeyBytes);
    }
}
