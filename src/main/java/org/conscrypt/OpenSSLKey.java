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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;

public class OpenSSLKey {
    private final NativeRef.EVP_PKEY ctx;

    private final OpenSSLEngine engine;

    private final String alias;

    private final boolean wrapped;

    public OpenSSLKey(long ctx) {
        this(ctx, false);
    }

    public OpenSSLKey(long ctx, boolean wrapped) {
        this.ctx = new NativeRef.EVP_PKEY(ctx);
        engine = null;
        alias = null;
        this.wrapped = wrapped;
    }

    public OpenSSLKey(long ctx, OpenSSLEngine engine, String alias) {
        this.ctx = new NativeRef.EVP_PKEY(ctx);
        this.engine = engine;
        this.alias = alias;
        this.wrapped = false;
    }

    /**
     * Returns the EVP_PKEY context for use in JNI calls.
     */
    public NativeRef.EVP_PKEY getNativeRef() {
        return ctx;
    }

    OpenSSLEngine getEngine() {
        return engine;
    }

    boolean isEngineBased() {
        return engine != null;
    }

    public String getAlias() {
        return alias;
    }

    public boolean isWrapped() {
        return wrapped;
    }

    public static OpenSSLKey fromPrivateKey(PrivateKey key) throws InvalidKeyException {
        if (key instanceof OpenSSLKeyHolder) {
            return ((OpenSSLKeyHolder) key).getOpenSSLKey();
        }

        final String keyFormat = key.getFormat();
        if (keyFormat == null) {
            return wrapPrivateKey(key);
        } else if (!"PKCS#8".equals(key.getFormat())) {
            throw new InvalidKeyException("Unknown key format " + keyFormat);
        }

        final byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        return new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(key.getEncoded()));
    }

    /**
     * Gets an {@code OpenSSLKey} instance backed by the provided private key. The resulting key is
     * usable only by this provider's TLS/SSL stack.
     *
     * @param privateKey private key.
     * @param publicKey corresponding public key or {@code null} if not available. Some opaque
     *        private keys cannot be used by the TLS/SSL stack without the public key.
     */
    public static OpenSSLKey fromPrivateKeyForTLSStackOnly(
            PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException {
        OpenSSLKey result = getOpenSSLKey(privateKey);
        if (result != null) {
            return result;
        }

        result = fromKeyMaterial(privateKey);
        if (result != null) {
            return result;
        }

        return wrapJCAPrivateKeyForTLSStackOnly(privateKey, publicKey);
    }

    /**
     * Gets an {@code OpenSSLKey} instance backed by the provided EC private key. The resulting key
     * is usable only by this provider's TLS/SSL stack.
     *
     * @param key private key.
     * @param ecParams EC parameters {@code null} if not available. Some opaque private keys cannot
     *        be used by the TLS/SSL stack without the parameters because the private key itself
     *        might not expose the parameters.
     */
    public static OpenSSLKey fromECPrivateKeyForTLSStackOnly(
            PrivateKey key, ECParameterSpec ecParams) throws InvalidKeyException {
        OpenSSLKey result = getOpenSSLKey(key);
        if (result != null) {
            return result;
        }

        result = fromKeyMaterial(key);
        if (result != null) {
            return result;
        }

        return OpenSSLECPrivateKey.wrapJCAPrivateKeyForTLSStackOnly(key, ecParams);
    }

    /**
     * Gets the {@code OpenSSLKey} instance of the provided key.
     *
     * @return instance or {@code null} if the {@code key} is not backed by OpenSSL's
     *         {@code EVP_PKEY}.
     */
    private static OpenSSLKey getOpenSSLKey(PrivateKey key) {
        if (key instanceof OpenSSLKeyHolder) {
            return ((OpenSSLKeyHolder) key).getOpenSSLKey();
        }

        if ("RSA".equals(key.getAlgorithm())) {
            return Platform.wrapRsaKey(key);
        }

        return null;
    }

    /**
     * Gets an {@code OpenSSLKey} instance initialized with the key material of the provided key.
     *
     * @return instance or {@code null} if the {@code key} does not export its key material in a
     *         suitable format.
     */
    private static OpenSSLKey fromKeyMaterial(PrivateKey key) {
        if (!"PKCS#8".equals(key.getFormat())) {
            return null;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            return null;
        }
        return new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(encoded));
    }

    /**
     * Wraps the provided private key for use in the TLS/SSL stack only. Sign/decrypt operations
     * using the key will be delegated to the {@code Signature}/{@code Cipher} implementation of the
     * provider which accepts the key.
     */
    private static OpenSSLKey wrapJCAPrivateKeyForTLSStackOnly(PrivateKey privateKey,
            PublicKey publicKey) throws InvalidKeyException {
        String keyAlgorithm = privateKey.getAlgorithm();
        if ("RSA".equals(keyAlgorithm)) {
            return OpenSSLRSAPrivateKey.wrapJCAPrivateKeyForTLSStackOnly(privateKey, publicKey);
        } else if ("EC".equals(keyAlgorithm)) {
            return OpenSSLECPrivateKey.wrapJCAPrivateKeyForTLSStackOnly(privateKey, publicKey);
        } else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    private static OpenSSLKey wrapPrivateKey(PrivateKey key) throws InvalidKeyException {
        if (key instanceof RSAPrivateKey) {
            return OpenSSLRSAPrivateKey.wrapPlatformKey((RSAPrivateKey) key);
        } else if (key instanceof ECPrivateKey) {
            return OpenSSLECPrivateKey.wrapPlatformKey((ECPrivateKey) key);
        } else {
            throw new InvalidKeyException("Unknown key type: " + key.toString());
        }
    }

    public static OpenSSLKey fromPublicKey(PublicKey key) throws InvalidKeyException {
        if (key instanceof OpenSSLKeyHolder) {
            return ((OpenSSLKeyHolder) key).getOpenSSLKey();
        }

        if (!"X.509".equals(key.getFormat())) {
            throw new InvalidKeyException("Unknown key format " + key.getFormat());
        }

        final byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        try {
            return new OpenSSLKey(NativeCrypto.d2i_PUBKEY(key.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeConstants.EVP_PKEY_RSA:
                return new OpenSSLRSAPublicKey(this);
            case NativeConstants.EVP_PKEY_EC:
                return new OpenSSLECPublicKey(this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    static PublicKey getPublicKey(X509EncodedKeySpec keySpec, int type)
            throws InvalidKeySpecException {
        X509EncodedKeySpec x509KeySpec = keySpec;

        final OpenSSLKey key;
        try {
            key = new OpenSSLKey(NativeCrypto.d2i_PUBKEY(x509KeySpec.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }

        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef()) != type) {
            throw new InvalidKeySpecException("Unexpected key type");
        }

        try {
            return key.getPublicKey();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeConstants.EVP_PKEY_RSA:
                return new OpenSSLRSAPrivateKey(this);
            case NativeConstants.EVP_PKEY_EC:
                return new OpenSSLECPrivateKey(this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    static PrivateKey getPrivateKey(PKCS8EncodedKeySpec keySpec, int type)
            throws InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8KeySpec = keySpec;

        final OpenSSLKey key;
        try {
            key = new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(pkcs8KeySpec.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }

        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef()) != type) {
            throw new InvalidKeySpecException("Unexpected key type");
        }

        try {
            return key.getPrivateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public SecretKey getSecretKey(String algorithm) throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeConstants.EVP_PKEY_HMAC:
                return new OpenSSLSecretKey(algorithm, this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof OpenSSLKey)) {
            return false;
        }

        OpenSSLKey other = (OpenSSLKey) o;
        if (ctx.equals(other.getNativeRef())) {
            return true;
        }

        /*
         * ENGINE-based keys must be checked in a special way.
         */
        if (engine == null) {
            if (other.getEngine() != null) {
                return false;
            }
        } else if (!engine.equals(other.getEngine())) {
            return false;
        } else {
            if (alias != null) {
                return alias.equals(other.getAlias());
            } else if (other.getAlias() != null) {
                return false;
            }
        }

        return NativeCrypto.EVP_PKEY_cmp(ctx, other.getNativeRef()) == 1;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 17 + ctx.hashCode();
        hash = hash * 31 + (int) (engine == null ? 0 : engine.getEngineContext());
        return hash;
    }
}
