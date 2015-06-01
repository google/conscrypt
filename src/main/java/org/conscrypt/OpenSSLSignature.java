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
        RSA, EC,
    };

    private NativeRef.EVP_MD_CTX ctx;

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
    private final long evpAlgorithm;

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
    private OpenSSLSignature(long algorithm, EngineType engineType)
            throws NoSuchAlgorithmException {
        this.engineType = engineType;
        this.evpAlgorithm = algorithm;
    }

    private final void resetContext() {
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_MD_CTX_init(ctxLocal);
        if (signing) {
            enableDSASignatureNonceHardeningIfApplicable();
            NativeCrypto.EVP_SignInit(ctxLocal, evpAlgorithm);
        } else {
            NativeCrypto.EVP_VerifyInit(ctxLocal, evpAlgorithm);
        }
        this.ctx = ctxLocal;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (signing) {
            NativeCrypto.EVP_SignUpdate(ctxLocal, input, offset, len);
        } else {
            NativeCrypto.EVP_VerifyUpdate(ctxLocal, input, offset, len);
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private void checkEngineType(OpenSSLKey pkey) throws InvalidKeyException {
        final int pkeyType = NativeCrypto.EVP_PKEY_type(pkey.getNativeRef());

        switch (engineType) {
            case RSA:
                if (pkeyType != NativeConstants.EVP_PKEY_RSA) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not RSA)");
                }
                break;
            case EC:
                if (pkeyType != NativeConstants.EVP_PKEY_EC) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not EC)");
                }
                break;
            default:
                throw new InvalidKeyException("Key must be of type " + engineType);
        }
    }

    private void initInternal(OpenSSLKey newKey, boolean signing) throws InvalidKeyException {
        checkEngineType(newKey);
        key = newKey;

        this.signing = signing;
        resetContext();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPrivateKey(privateKey), true);
    }

    /**
     * Enables a mitigation against private key leakage through ECDSA
     * signatures when weak nonces (per-message k values) are used. To mitigate
     * the issue, private key and message being signed is mixed into the
     * randomly generated nonce (k).
     *
     * <p>Does nothing for signatures that are not ECDSA.
     */
    private void enableDSASignatureNonceHardeningIfApplicable() {
        final OpenSSLKey key = this.key;
        switch (engineType) {
            case EC:
                NativeCrypto.EC_KEY_set_nonce_from_hash(key.getNativeRef(), true);
                break;
            default:
                // Hardening not applicable
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPublicKey(publicKey), false);
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need RSA or EC private key");
        }

        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        try {
            byte[] buffer = new byte[NativeCrypto.EVP_PKEY_size(key.getNativeRef())];
            int bytesWritten = NativeCrypto.EVP_SignFinal(ctxLocal, buffer, 0,
                    key.getNativeRef());

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
            resetContext();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need RSA or EC public key");
        }

        try {
            int result = NativeCrypto.EVP_VerifyFinal(ctx, sigBytes, 0, sigBytes.length,
                    key.getNativeRef());
            return result == 1;
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after
             * verify calls.
             */
            resetContext();
        }
    }

    public static final class MD5RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("MD5");
        public MD5RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA1RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA1");
        public SHA1RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA224RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA224");
        public SHA224RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA256RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA256");
        public SHA256RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA384RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA384");
        public SHA384RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA512RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA512");
        public SHA512RSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA1ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA1");
        public SHA1ECDSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA224ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA224");
        public SHA224ECDSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA256ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA256");
        public SHA256ECDSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA384ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA384");
        public SHA384ECDSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA512ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA512");
        public SHA512ECDSA() throws NoSuchAlgorithmException {
            super(EVP_MD, EngineType.EC);
        }
    }
}

