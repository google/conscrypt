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

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.Arrays;

/** An OpenSSL ML-DSA public key. */
public class OpenSslMlDsaPublicKey implements PublicKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 453861992373478445L;

    private byte[] raw = null; // only set when the key is serialized or deserialized.
    private transient MlDsaAlgorithm algorithm;
    private transient OpenSSLKey key;

    private static boolean isValid(byte[] raw, MlDsaAlgorithm algorithm) {
        return raw.length == algorithm.publicKeySize();
    }

    private static MlDsaAlgorithm getAlgorithmFromRaw(byte[] raw) {
        if (raw.length == MlDsaAlgorithm.ML_DSA_65.publicKeySize()) {
            return MlDsaAlgorithm.ML_DSA_65;
        }
        if (raw.length == MlDsaAlgorithm.ML_DSA_87.publicKeySize()) {
            return MlDsaAlgorithm.ML_DSA_87;
        }
        throw new IllegalArgumentException("Invalid raw key of length " + raw.length);
    }

    private static OpenSSLKey getOpenSslKeyFromRaw(byte[] raw, MlDsaAlgorithm algorithm)
            throws ParsingException {
        return new OpenSSLKey(NativeCrypto.EVP_PKEY_from_raw_public_key(
                OpenSslMlDsaKeyFactory.getPKeyType(algorithm), raw));
    }

    OpenSslMlDsaPublicKey(OpenSSLKey key, MlDsaAlgorithm algorithm) {
        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef())
            != OpenSslMlDsaKeyFactory.getPKeyType(algorithm)) {
            throw new IllegalArgumentException("Invalid key type");
        }
        this.algorithm = algorithm;
        this.key = key;
    }

    public OpenSslMlDsaPublicKey(byte[] raw, MlDsaAlgorithm algorithm) {
        this.algorithm = algorithm;
        try {
            this.key = getOpenSslKeyFromRaw(raw, algorithm);
        } catch (ParsingException e) {
            throw new IllegalArgumentException("Invalid key", e);
        }
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
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_marshal_public_key(key.getNativeRef());
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    byte[] getRaw() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_PKEY_get_raw_public_key(key.getNativeRef());
    }

    @Override
    public boolean equals(Object o) {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslMlDsaPublicKey)) {
            return false;
        }
        OpenSslMlDsaPublicKey that = (OpenSslMlDsaPublicKey) o;

        // different algorithms have different raw key lengths, so we only need to compare the raw
        // key.
        return Arrays.equals(getRaw(), that.getRaw());
    }

    @Override
    public int hashCode() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return Arrays.hashCode(getRaw());
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject(); // reads "this.raw"
        this.algorithm = getAlgorithmFromRaw(this.raw);
        if (!isValid(this.raw, this.algorithm)) {
            throw new IOException("Invalid key");
        }
        try {
            this.key = getOpenSslKeyFromRaw(this.raw, this.algorithm);
        } catch (ParsingException e) {
            throw new IOException("Invalid key", e);
        }
        this.raw = null;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        synchronized (this) {
            this.raw = NativeCrypto.EVP_PKEY_get_raw_public_key(key.getNativeRef());
            stream.defaultWriteObject(); // writes "raw"
            this.raw = null;
        }
    }
}
