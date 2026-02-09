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
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/** An OpenSSL EdDSA private key. */
public class OpenSslEdDsaPrivateKey implements PrivateKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = -3136201500221850916L;

    private byte[] privateKeyBytes = null; // only set when the key is serialized or deserialized.
    private transient OpenSSLKey key;

    private static OpenSSLKey getOpenSslKeyFromPkcS8(byte[] pkcs8Encoded) throws ParsingException {
        return new OpenSSLKey(NativeCrypto.EVP_PKEY_from_private_key_info(
                pkcs8Encoded, new int[] {NativeConstants.EVP_PKEY_ED25519}));
    }

    private static OpenSSLKey getOpenSslKeyFromRaw(byte[] raw) throws ParsingException {
        return new OpenSSLKey(
                NativeCrypto.EVP_PKEY_from_raw_private_key(NativeConstants.EVP_PKEY_ED25519, raw));
    }

    public OpenSslEdDsaPrivateKey(EncodedKeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec.getFormat().equalsIgnoreCase("raw")) {
                key = getOpenSslKeyFromRaw(keySpec.getEncoded());
            } else if (keySpec.getFormat().equals("PKCS#8")) {
                key = getOpenSslKeyFromPkcS8(keySpec.getEncoded());
            } else {
                throw new InvalidKeySpecException("Encoding must be in PKCS#8 or raw format");
            }
        } catch (ParsingException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public OpenSslEdDsaPrivateKey(byte[] raw) {
        try {
            key = getOpenSslKeyFromRaw(raw);
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
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_marshal_private_key(key.getNativeRef());
    }

    byte[] getRaw() {
        if (key == null) {
            throw new IllegalStateException("key is destroyed");
        }
        return NativeCrypto.EVP_PKEY_get_raw_private_key(key.getNativeRef());
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    @Override
    public void destroy() {
        key = null;
    }

    @Override
    public boolean isDestroyed() {
        return key == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OpenSslEdDsaPrivateKey)) {
            return false;
        }
        OpenSslEdDsaPrivateKey that = (OpenSslEdDsaPrivateKey) o;
        return Arrays.equals(getRaw(), that.getRaw());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getRaw());
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject(); // reads "privateKeyBytes"
        try {
            key = getOpenSslKeyFromRaw(privateKeyBytes);
        } catch (ParsingException e) {
            throw new IllegalArgumentException("Parsing raw key failed", e);
        }
        privateKeyBytes = null;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        synchronized (this) {
            privateKeyBytes = getRaw();
            stream.defaultWriteObject(); // writes "privateKeyBytes"
            privateKeyBytes = null;
        }
    }
}
