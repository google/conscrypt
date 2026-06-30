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
import java.security.PrivateKey;
import java.util.Arrays;

/** A SLH-DSA private key. */
public class OpenSslSlhDsaPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 0x87e8776a4491fecbL;

    static final int PRIVATE_KEY_SIZE_BYTES = 64;

    private byte[] raw;

    public OpenSslSlhDsaPrivateKey(byte[] raw) {
        if (raw.length != PRIVATE_KEY_SIZE_BYTES) {
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return ArrayUtils.concat(OpenSslSlhDsaKeyFactory.pkcs8Preamble, raw);
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
        if (!(o instanceof OpenSslSlhDsaPrivateKey)) {
            return false;
        }
        OpenSslSlhDsaPrivateKey that = (OpenSslSlhDsaPrivateKey) o;
        return Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject(); // reads "raw"
        if (raw.length != PRIVATE_KEY_SIZE_BYTES) {
            throw new IOException("Invalid key size");
        }
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject(); // writes "raw"
    }
}
