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

import java.io.InputStream;
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
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

/**
 * Represents a BoringSSL {@code EVP_PKEY}.
 */
@Internal
public final class OpenSSLKey {
    private final NativeRef.EVP_PKEY ctx;

    private final boolean wrapped;

    // If true, indicates that this key is hardware-backed, e.g. stored in a TEE keystore.
    // Conscrypt never creates such keys, but setting this field to true allows developers
    // to create an EVP_PKEY from a hardware-backed key and then create an OpenSSLKey from it
    // which can be used with Conscrypt.
    // Hardware-backed keys cannot be serialised or have any private key material extracted.
    private final boolean hardwareBacked;

    OpenSSLKey(long ctx) {
        this(ctx, false);
    }

    OpenSSLKey(long ctx, boolean wrapped) {
        this(ctx, wrapped, false);
    }

    // Constructor for users who need to set the |hardwareBacked| field to true.
    // See the field documentation for more information.
    OpenSSLKey(long ctx, boolean wrapped, boolean hardwareBacked) {
        this.ctx = new NativeRef.EVP_PKEY(ctx);
        this.wrapped = wrapped;
        this.hardwareBacked = hardwareBacked;
    }

    /**
     * Returns the EVP_PKEY context for use in JNI calls.
     */
    NativeRef.EVP_PKEY getNativeRef() {
        return ctx;
    }

    boolean isWrapped() {
        return wrapped;
    }

    boolean isHardwareBacked() {
        return hardwareBacked;
    }

    static OpenSSLKey fromPrivateKey(PrivateKey key) throws InvalidKeyException {
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

        try {
            return new OpenSSLKey(NativeCrypto.EVP_parse_private_key(key.getEncoded()));
        } catch (ParsingException e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
     * Parse a private key in PEM encoding from the provided input stream.
     *
     * @throws InvalidKeyException if parsing fails
     */
    static OpenSSLKey fromPrivateKeyPemInputStream(InputStream is)
            throws InvalidKeyException {
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
        try {
            long keyCtx = NativeCrypto.PEM_read_bio_PrivateKey(bis.getBioContext());
            if (keyCtx == 0L) {
                return null;
            }

            return new OpenSSLKey(keyCtx);
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        } finally {
            bis.release();
        }
    }

    /**
     * Gets an {@code OpenSSLKey} instance backed by the provided private key. The resulting key is
     * usable only by this provider's TLS/SSL stack.
     *
     * @param privateKey private key.
     * @param publicKey corresponding public key or {@code null} if not available. Some opaque
     *        private keys cannot be used by the TLS/SSL stack without the public key.
     */
    static OpenSSLKey fromPrivateKeyForTLSStackOnly(
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
    static OpenSSLKey fromECPrivateKeyForTLSStackOnly(
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
        return null;
    }

    /**
     * Gets an {@code OpenSSLKey} instance initialized with the key material of the provided key.
     *
     * @return instance or {@code null} if the {@code key} does not export its key material in a
     *         suitable format.
     */
    private static OpenSSLKey fromKeyMaterial(PrivateKey key) throws InvalidKeyException {
        if (!"PKCS#8".equals(key.getFormat())) {
            return null;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            return null;
        }
        try {
            return new OpenSSLKey(NativeCrypto.EVP_parse_private_key(encoded));
        } catch (ParsingException e) {
            throw new InvalidKeyException(e);
        }
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

    static OpenSSLKey fromPublicKey(PublicKey key) throws InvalidKeyException {
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
            return new OpenSSLKey(NativeCrypto.EVP_parse_public_key(key.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
     * Parse a public key in PEM encoding from the provided input stream.
     *
     * @throws InvalidKeyException if parsing fails
     */
    public static OpenSSLKey fromPublicKeyPemInputStream(InputStream is)
            throws InvalidKeyException {
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
        try {
            long keyCtx = NativeCrypto.PEM_read_bio_PUBKEY(bis.getBioContext());
            if (keyCtx == 0L) {
                return null;
            }

            return new OpenSSLKey(keyCtx);
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        } finally {
            bis.release();
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
            key = new OpenSSLKey(NativeCrypto.EVP_parse_public_key(x509KeySpec.getEncoded()));
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

    PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeConstants.EVP_PKEY_RSA:
                return OpenSSLRSAPrivateKey.getInstance(this);
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
            key = new OpenSSLKey(NativeCrypto.EVP_parse_private_key(pkcs8KeySpec.getEncoded()));
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

        return NativeCrypto.EVP_PKEY_cmp(ctx, other.getNativeRef()) == 1;
    }

    @Override
    public int hashCode() {
        return ctx.hashCode();
    }
}
