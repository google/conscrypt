/*
 * Copyright (C) 2008 The Android Open Source Project
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
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Implements the subset of the JDK Signature interface needed for
 * signature verification using OpenSSL.
 */
public class OpenSSLSignature extends SignatureSpi {
    private static enum EngineType {
        RSA, DSA, EC,
    };

    /**
     * Holds a pointer to the native message digest context.
     */
    private long ctx;

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Holds the type of the Java algorithm.
     */
    private final EngineType engineType;

    /**
     * Holds the OpenSSL name of the algorithm (lower case, no dashes).
     */
    private final String evpAlgorithm;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * True when engine is initialized to signing.
     */
    private boolean signing;

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *
     * @param algorithm OpenSSL name of the algorithm, e.g. "RSA-SHA1".
     */
    private OpenSSLSignature(String algorithm, EngineType engineType)
            throws NoSuchAlgorithmException {
        // We don't support MD2
        if ("RSA-MD2".equals(algorithm)) {
            throw new NoSuchAlgorithmException(algorithm);
        }

        this.engineType = engineType;
        this.evpAlgorithm = algorithm;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (signing) {
            if (ctx == 0) {
                try {
                    ctx = NativeCrypto.EVP_SignInit(evpAlgorithm);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }

            NativeCrypto.EVP_SignUpdate(ctx, input, offset, len);
        } else {
            if (ctx == 0) {
                try {
                    ctx = NativeCrypto.EVP_VerifyInit(evpAlgorithm);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }

            NativeCrypto.EVP_VerifyUpdate(ctx, input, offset, len);
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private void checkEngineType(OpenSSLKey pkey) throws InvalidKeyException {
        final int pkeyType = NativeCrypto.EVP_PKEY_type(pkey.getPkeyContext());

        switch (engineType) {
            case RSA:
                if (pkeyType != NativeCrypto.EVP_PKEY_RSA) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not RSA)");
                }
                break;
            case DSA:
                if (pkeyType != NativeCrypto.EVP_PKEY_DSA) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not DSA)");
                }
                break;
            case EC:
                if (pkeyType != NativeCrypto.EVP_PKEY_EC) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not EC)");
                }
                break;
            default:
                throw new InvalidKeyException("Key must be of type " + engineType);
        }
    }

    private void initInternal(OpenSSLKey newKey) throws InvalidKeyException {
        destroyContextIfExists();
        checkEngineType(newKey);
        key = newKey;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPrivateKey(privateKey));
        enableDSASignatureNonceHardeningIfApplicable();
        signing = true;
    }

    /**
     * Enables a mitigation against private key leakage through DSA and ECDSA signatures when weak
     * nonces (per-message k values) are used. To mitigate the issue, private key and message being
     * signed is mixed into the randomly generated nonce (k).
     *
     * <p>Does nothing for signatures that are neither DSA nor ECDSA.
     */
    private void enableDSASignatureNonceHardeningIfApplicable() {
        switch (engineType) {
            case DSA:
                NativeCrypto.set_DSA_flag_nonce_from_hash(key.getPkeyContext());
                break;
            case EC:
                NativeCrypto.EC_KEY_set_nonce_from_hash(key.getPkeyContext(), true);
                break;
            default:
              // Hardening not applicable
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPublicKey(publicKey));
        signing = false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need DSA or RSA or EC private key");
        }

        try {
            byte[] buffer = new byte[NativeCrypto.EVP_PKEY_size(key.getPkeyContext())];
            int bytesWritten = NativeCrypto.EVP_SignFinal(ctx, buffer, 0, key.getPkeyContext());

            byte[] signature = new byte[bytesWritten];
            System.arraycopy(buffer, 0, signature, 0, bytesWritten);

            return signature;
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after sign
             * calls.
             */
            destroyContextIfExists();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need DSA or RSA public key");
        }

        try {
            int result = NativeCrypto.EVP_VerifyFinal(ctx, sigBytes, 0, sigBytes.length,
                    key.getPkeyContext());
            return result == 1;
        } catch (Exception ex) {
            return false;
        } finally {
            /*
             * Java expects the digest context to be reset completely after
             * verify calls.
             */
            destroyContextIfExists();
        }
    }

    private void destroyContextIfExists() {
        if (ctx != 0) {
            NativeCrypto.EVP_MD_CTX_destroy(ctx);
            ctx = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (ctx != 0) {
                NativeCrypto.EVP_MD_CTX_destroy(ctx);
            }
        } finally {
            super.finalize();
        }
    }

    public static final class MD5RSA extends OpenSSLSignature {
        public MD5RSA() throws NoSuchAlgorithmException {
            super("RSA-MD5", EngineType.RSA);
        }
    }
    public static final class SHA1RSA extends OpenSSLSignature {
        public SHA1RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA1", EngineType.RSA);
        }
    }
    public static final class SHA224RSA extends OpenSSLSignature {
        public SHA224RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA224", EngineType.RSA);
        }
    }
    public static final class SHA256RSA extends OpenSSLSignature {
        public SHA256RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA256", EngineType.RSA);
        }
    }
    public static final class SHA384RSA extends OpenSSLSignature {
        public SHA384RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA384", EngineType.RSA);
        }
    }
    public static final class SHA512RSA extends OpenSSLSignature {
        public SHA512RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA512", EngineType.RSA);
        }
    }
    public static final class SHA1DSA extends OpenSSLSignature {
        public SHA1DSA() throws NoSuchAlgorithmException {
            super("DSA-SHA1", EngineType.DSA);
        }
    }
    public static final class SHA1ECDSA extends OpenSSLSignature {
        public SHA1ECDSA() throws NoSuchAlgorithmException {
            super("SHA1", EngineType.EC);
        }
    }
    public static final class SHA224ECDSA extends OpenSSLSignature {
        public SHA224ECDSA() throws NoSuchAlgorithmException {
            super("SHA224", EngineType.EC);
        }
    }
    public static final class SHA256ECDSA extends OpenSSLSignature {
        public SHA256ECDSA() throws NoSuchAlgorithmException {
            super("SHA256", EngineType.EC);
        }
    }
    public static final class SHA384ECDSA extends OpenSSLSignature {
        public SHA384ECDSA() throws NoSuchAlgorithmException {
            super("SHA384", EngineType.EC);
        }
    }
    public static final class SHA512ECDSA extends OpenSSLSignature {
        public SHA512ECDSA() throws NoSuchAlgorithmException {
            super("SHA512", EngineType.EC);
        }
    }
}

