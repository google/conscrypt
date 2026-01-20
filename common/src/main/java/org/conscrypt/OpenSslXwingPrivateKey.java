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
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An X-Wing private key. */
public class OpenSslXwingPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;

    static final int PRIVATE_KEY_SIZE_BYTES = 32;

    // The PKCS#8 encoding of a X-Wing private key is always the concatenation of a fixed
    // prefix and the raw key.
    private static final byte[] pkcs8Preamble = new byte[] {
            0x30,
            0x34,
            0x02,
            0x01,
            0x00,
            0x30,
            0x0d,
            0x06,
            0x0b,
            0x2b,
            0x06,
            0x01,
            0x04,
            0x01,
            (byte) 0x83,
            (byte) 0xe6,
            0x2d,
            (byte) 0x81,
            (byte) 0xc8,
            (byte) 0x7a,
            0x04,
            0x20,
    };

    private byte[] raw;

    public OpenSslXwingPrivateKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        byte[] encoded = keySpec.getEncoded();
        if (keySpec.getFormat().equals("PKCS#8")) {
            byte[] preamble = Arrays.copyOf(encoded, pkcs8Preamble.length);
            if (!Arrays.equals(preamble, pkcs8Preamble)) {
                throw new InvalidKeySpecException("Invalid X-Wing PKCS8 key preamble");
            }
            raw = Arrays.copyOfRange(encoded, pkcs8Preamble.length, encoded.length);
            if (raw.length != PRIVATE_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
        } else if (keySpec.getFormat().equalsIgnoreCase("raw")) {
            if (encoded.length != PRIVATE_KEY_SIZE_BYTES) {
                throw new InvalidKeySpecException("Invalid key size");
            }
            raw = encoded;
        } else {
            throw new InvalidKeySpecException("Encoding must be in raw format");
        }
    }

    public OpenSslXwingPrivateKey(byte[] raw) {
        if (raw.length != PRIVATE_KEY_SIZE_BYTES) {
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return ArrayUtils.concat(pkcs8Preamble, raw);
    }

    byte[] getRaw() {
        if (raw == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return raw.clone();
    }

    @Override
    public void destroy() {
        if (raw != null) {
            Arrays.fill(raw, (byte) 0);
            raw = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return raw == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslXwingPrivateKey)) {
            return false;
        }
        OpenSslXwingPrivateKey that = (OpenSslXwingPrivateKey) o;
        return MessageDigest.isEqual(raw, that.raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    private void readObject(ObjectInputStream in) {
        throw new UnsupportedOperationException("serialization not supported");
    }

    private void writeObject(ObjectOutputStream out) {
        throw new UnsupportedOperationException("serialization not supported");
    }
}
