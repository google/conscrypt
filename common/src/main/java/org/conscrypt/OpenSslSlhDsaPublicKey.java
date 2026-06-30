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
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.Arrays;

/** An SLH-DSA public key. */
public class OpenSslSlhDsaPublicKey implements PublicKey {
    private static final long serialVersionUID = 0x4589aa00e279d127L;

    static final int PUBLIC_KEY_SIZE_BYTES = 32;

    private final byte[] raw;

    public OpenSslSlhDsaPublicKey(byte[] raw) {
        if (raw.length != PUBLIC_KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size");
        }
        this.raw = raw.clone();
    }

    @Override
    public String getAlgorithm() {
        return "SLH-DSA-SHA2-128S";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return ArrayUtils.concat(OpenSslSlhDsaKeyFactory.x509Preamble, raw);
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
        if (!(o instanceof OpenSslSlhDsaPublicKey)) {
            return false;
        }
        OpenSslSlhDsaPublicKey that = (OpenSslSlhDsaPublicKey) o;
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
        stream.defaultReadObject(); // reads "raw"
        if (raw.length != PUBLIC_KEY_SIZE_BYTES) {
            throw new IOException("Invalid key size");
        }
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject(); // writes "raw"
    }
}
