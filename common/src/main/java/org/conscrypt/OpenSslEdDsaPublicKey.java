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
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An OpenSSL EdDSA public key. */
public class OpenSslEdDsaPublicKey implements PublicKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 453861992373478445L;

    private byte[] publicKeyBytes = null; // only set when the key is serialized or deserialized.
    private transient OpenSSLKey key;

    private static OpenSSLKey getOpenSslKeyFromX509(byte[] x509Encoded) throws ParsingException {
        return new OpenSSLKey(NativeCrypto.EVP_PKEY_from_subject_public_key_info(
                x509Encoded, new int[] {NativeConstants.EVP_PKEY_ED25519}));
    }

    private static OpenSSLKey getOpenSslKeyFromRaw(byte[] raw) throws ParsingException {
        return new OpenSSLKey(
                NativeCrypto.EVP_PKEY_from_raw_public_key(NativeConstants.EVP_PKEY_ED25519, raw));
    }

    public OpenSslEdDsaPublicKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec.getFormat().equalsIgnoreCase("raw")) {
                key = getOpenSslKeyFromRaw(keySpec.getEncoded());
            } else if (keySpec.getFormat().equals("X.509")) {
                key = getOpenSslKeyFromX509(keySpec.getEncoded());
            } else {
                throw new InvalidKeySpecException("Encoding must be in X.509 or raw format");
            }
        } catch (ParsingException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public OpenSslEdDsaPublicKey(byte[] coordinateBytes) {
        try {
            key = getOpenSslKeyFromRaw(coordinateBytes);
        } catch (ParsingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // This intentionally diverges from the OpenJDK implementation and JEP 339 (which return
    // "EdDSA") to achieve backwards compatibility with the "AndroidKeyStore" provider, which
    // supported generation of Ed25519 keys before Conscrypt did. Conscrypt's `getSigAlgName()`
    // method returns the OID if there is no mapping to an algorithm name and the "AndroidKeyStore"
    // provider therefore expects the OID as the algorithm name, even if Conscrypt now supports
    // Ed25519 key generation (which otherwise aligns with JEP 339).
    @Override
    public String getAlgorithm() {
        return "1.3.101.112";
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

    byte[] getRaw() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_PKEY_get_raw_public_key(key.getNativeRef());
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }

        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslEdDsaPublicKey)) {
            return false;
        }
        OpenSslEdDsaPublicKey that = (OpenSslEdDsaPublicKey) o;
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
        stream.defaultReadObject(); // reads "publicKeyBytes"
        try {
            key = getOpenSslKeyFromRaw(publicKeyBytes);
        } catch (ParsingException e) {
            throw new IllegalArgumentException("Parsing raw key failed", e);
        }
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        synchronized (this) {
            this.publicKeyBytes = getRaw();
            stream.defaultWriteObject(); // writes "publicKeyBytes"
            this.publicKeyBytes = null;
        }
    }
}
