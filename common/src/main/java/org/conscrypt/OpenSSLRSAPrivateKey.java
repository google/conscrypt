/*
 * Copyright (C) 2012 The Android Open Source Project
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
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

/**
 * An implementation of {@link java.security.PrivateKey} for RSA keys which uses BoringSSL to
 * perform all the operations.
 */
class OpenSSLRSAPrivateKey implements RSAPrivateKey, OpenSSLKeyHolder {
    private static final long serialVersionUID = 4872170254439578735L;

    transient OpenSSLKey key;

    transient boolean fetchedParams;

    BigInteger modulus;

    BigInteger privateExponent;

    OpenSSLRSAPrivateKey(OpenSSLKey key) {
        this.key = key;
    }

    OpenSSLRSAPrivateKey(OpenSSLKey key, byte[][] params) {
        this(key);
        readParams(params);
        fetchedParams = true;
    }

    @Override
    public OpenSSLKey getOpenSSLKey() {
        return key;
    }

    public OpenSSLRSAPrivateKey(RSAPrivateKeySpec rsaKeySpec) throws InvalidKeySpecException {
        this(init(rsaKeySpec));
    }

    private static OpenSSLKey init(RSAPrivateKeySpec rsaKeySpec) throws InvalidKeySpecException {
        final BigInteger modulus = rsaKeySpec.getModulus();
        final BigInteger privateExponent = rsaKeySpec.getPrivateExponent();

        if (modulus == null) {
            throw new InvalidKeySpecException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeySpecException("privateExponent == null");
        }

        try {
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                    modulus.toByteArray(),
                    null,
                    privateExponent.toByteArray(),
                    null,
                    null,
                    null,
                    null,
                    null));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    static OpenSSLRSAPrivateKey getInstance(OpenSSLKey key) {
        byte[][] params = NativeCrypto.get_RSA_private_params(key.getNativeRef());
        if (params[1] != null) {
            return new OpenSSLRSAPrivateCrtKey(key, params);
        }
        return new OpenSSLRSAPrivateKey(key, params);
    }

    static OpenSSLKey wrapPlatformKey(RSAPrivateKey rsaPrivateKey) {
        return new OpenSSLKey(NativeCrypto.getRSAPrivateKeyWrapper(rsaPrivateKey, rsaPrivateKey
                .getModulus().toByteArray()), true);
    }

    /**
     * Wraps the provided private key for use in the TLS/SSL stack only. Sign/decrypt operations
     * using the key will be delegated to the {@code Signature}/{@code Cipher} implementation of the
     * provider which accepts the key.
     */
    static OpenSSLKey wrapJCAPrivateKeyForTLSStackOnly(PrivateKey privateKey,
            PublicKey publicKey) throws InvalidKeyException {
        BigInteger modulus = null;
        if (privateKey instanceof RSAKey) {
            modulus = ((RSAKey) privateKey).getModulus();
        } else if (publicKey instanceof RSAKey) {
            modulus = ((RSAKey) publicKey).getModulus();
        }
        if (modulus == null) {
            throw new InvalidKeyException("RSA modulus not available. Private: " + privateKey
                    + ", public: " + publicKey);
        }
        return new OpenSSLKey(
                NativeCrypto.getRSAPrivateKeyWrapper(privateKey, modulus.toByteArray()), true);
    }

    static OpenSSLKey getInstance(RSAPrivateKey rsaPrivateKey) throws InvalidKeyException {
        /*
         * If the key is not encodable (PKCS11-like key), then wrap it and use
         * JNI upcalls to satisfy requests.
         */
        if (rsaPrivateKey.getFormat() == null) {
            return wrapPlatformKey(rsaPrivateKey);
        }

        final BigInteger modulus = rsaPrivateKey.getModulus();
        final BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();

        if (modulus == null) {
            throw new InvalidKeyException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeyException("privateExponent == null");
        }

        try {
            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                    modulus.toByteArray(),
                    null,
                    privateExponent.toByteArray(),
                    null,
                    null,
                    null,
                    null,
                    null));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    synchronized final void ensureReadParams() {
        if (fetchedParams) {
            return;
        }
        readParams(NativeCrypto.get_RSA_private_params(key.getNativeRef()));
        fetchedParams = true;
    }

    void readParams(byte[][] params) {
        if (params[0] == null) {
            throw new NullPointerException("modulus == null");
        } else if (params[2] == null && !key.isHardwareBacked()) {
            throw new NullPointerException("privateExponent == null");
        }

        modulus = new BigInteger(params[0]);

        // ENGINE-based keys are not guaranteed to have a private exponent.
        if (params[2] != null) {
            privateExponent = new BigInteger(params[2]);
        }
    }

    @Override
    public final BigInteger getPrivateExponent() {
        if (key.isHardwareBacked()) {
            throw new UnsupportedOperationException("Private exponent cannot be extracted");
        }
        ensureReadParams();
        return privateExponent;
    }

    @Override
    public final BigInteger getModulus() {
        ensureReadParams();
        return modulus;
    }

    @Override
    public final byte[] getEncoded() {
        if (key.isHardwareBacked()) {
            return null;
        }
        return NativeCrypto.EVP_marshal_private_key(key.getNativeRef());
    }

    @Override
    public final String getFormat() {
        if (key.isHardwareBacked()) {
            return null;
        }
        return "PKCS#8";
    }

    @Override
    public final String getAlgorithm() {
        return "RSA";
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof OpenSSLRSAPrivateKey) {
            OpenSSLRSAPrivateKey other = (OpenSSLRSAPrivateKey) o;
            return key.equals(other.getOpenSSLKey());
        }

        if (o instanceof RSAPrivateKey) {
            ensureReadParams();
            RSAPrivateKey other = (RSAPrivateKey) o;

            return modulus.equals(other.getModulus())
                    && privateExponent.equals(other.getPrivateExponent());
        }

        return false;
    }

    @Override
    public int hashCode() {
        ensureReadParams();
        int hash = 1;

        hash = hash * 3 + modulus.hashCode();
        if (privateExponent != null) {
            hash = hash * 7 + privateExponent.hashCode();
        }

        return hash;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OpenSSLRSAPrivateKey{");

        ensureReadParams();
        sb.append("modulus=");
        sb.append(modulus.toString(16));

        return sb.toString();
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                modulus.toByteArray(),
                null,
                privateExponent.toByteArray(),
                null,
                null,
                null,
                null,
                null));
        fetchedParams = true;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (key.isHardwareBacked()) {
            throw new NotSerializableException("Hardware backed keys can not be serialized");
        }
        ensureReadParams();
        stream.defaultWriteObject();
    }
}
