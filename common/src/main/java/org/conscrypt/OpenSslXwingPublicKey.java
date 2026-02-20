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
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An X-Wing public key. */
public class OpenSslXwingPublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;

    static final int PUBLIC_KEY_SIZE_BYTES = 1216;

    // The X.509 encoding of a X-Wing public key is always the concatenation of a fixed
    // prefix and the raw key.
    private static final byte[] x509Preamble = new byte[] {
            0x30,        (byte) 0x82, 0x04,        (byte) 0xd4, 0x30,        0x0d,
            0x06,        0x0b,        0x2b,        0x06,        0x01,        0x04,
            0x01,        (byte) 0x83, (byte) 0xe6, 0x2d,        (byte) 0x81, (byte) 0xc8,
            (byte) 0x7a, 0x03,        (byte) 0x82, 0x04,        (byte) 0xc1, 0x00,
    };

    private final byte[] raw;

    public OpenSslXwingPublicKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (keySpec.getFormat().equals("X.509")) {
            if (!ArrayUtils.startsWith(encoded, x509Preamble)) {
                throw new InvalidKeySpecException("Invalid X-Wing X.509 key preamble");
            }
            raw = Arrays.copyOfRange(encoded, x509Preamble.length, encoded.length);
            if (raw.length != PUBLIC_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
        } else if (keySpec.getFormat().equalsIgnoreCase("raw")) {
            if (encoded.length != PUBLIC_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            raw = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in raw format");
        }
    }

    public OpenSslXwingPublicKey(byte[] raw) {
        if (raw.length != PUBLIC_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.raw = raw.clone();
    }

    @Override
    public String getAlgorithm() {
        return "XWING";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return ArrayUtils.concat(x509Preamble, raw);
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
        if (!(o instanceof OpenSslXwingPublicKey)) {
            return false;
        }
        OpenSslXwingPublicKey that = (OpenSslXwingPublicKey) o;
        return Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(raw);
    }

    private void readObject(ObjectInputStream in) {
        throw new UnsupportedOperationException("serialization not supported");
    }

    private void writeObject(ObjectOutputStream out) {
        throw new UnsupportedOperationException("serialization not supported");
    }
}
