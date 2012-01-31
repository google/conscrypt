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

package org.apache.harmony.xnet.provider.jsse;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Implements the subset of the JDK Signature interface needed for
 * signature verification using OpenSSL.
 */
public class OpenSSLSignature extends Signature {
    /**
     * Holds a pointer to the native message digest context.
     */
    private int ctx;

    /**
     * Holds a pointer to the native DSA key.
     */
    private int dsa;

    /**
     * Holds a pointer to the native RSA key.
     */
    private int rsa;

    /**
     * Holds the OpenSSL name of the algorithm (lower case, no dashes).
     */
    private final String evpAlgorithm;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *
     * @param algorithm OpenSSL name of the algorithm, e.g. "RSA-SHA1".
     */
    private OpenSSLSignature(String algorithm) throws NoSuchAlgorithmException {
        super(algorithm);

        // We don't support MD2
        if ("RSA-MD2".equals(algorithm)) {
            throw new NoSuchAlgorithmException(algorithm);
        }

        this.evpAlgorithm = algorithm;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (ctx == 0) {
            try {
                ctx = NativeCrypto.EVP_SignInit(evpAlgorithm);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        if (state == SIGN) {
            NativeCrypto.EVP_SignUpdate(ctx, input, offset, len);
        } else {
            NativeCrypto.EVP_VerifyUpdate(ctx, input, offset, len);
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        destroyContextIfExists();
        freeKeysIfExist();

        if (privateKey instanceof DSAPrivateKey) {
            try {
                DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privateKey;
                DSAParams dsaParams = dsaPrivateKey.getParams();
                dsa = NativeCrypto.EVP_PKEY_new_DSA(
                        dsaParams.getP().toByteArray(),
                        dsaParams.getQ().toByteArray(),
                        dsaParams.getG().toByteArray(),
                        null,
                        dsaPrivateKey.getX().toByteArray());
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        } else if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;

            final BigInteger modulus = rsaPrivateKey.getModulus();
            final BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();

            if (modulus == null) {
                throw new InvalidKeyException("modulus == null");
            } else if (privateExponent == null) {
                throw new InvalidKeyException("privateExponent == null");
            }

            try {
                /*
                 * OpenSSL uses the public modulus to do RSA blinding. Regular
                 * RSAPrivateKey does not have the public modulus, so we can
                 * only possibly support RSAPrivateCrtKey without turning off
                 * blinding.
                 */
                final BigInteger publicExponent = rsaPrivateKey.getPublicExponent();
                final BigInteger primeP = rsaPrivateKey.getPrimeP();
                final BigInteger primeQ = rsaPrivateKey.getPrimeQ();

                rsa = NativeCrypto.EVP_PKEY_new_RSA(
                        modulus.toByteArray(),
                        publicExponent == null ? null : publicExponent.toByteArray(),
                        privateExponent.toByteArray(),
                        primeP == null ? null : primeP.toByteArray(),
                        primeQ == null ? null : primeQ.toByteArray());
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        } else if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

            final BigInteger modulus = rsaPrivateKey.getModulus();
            final BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();

            if (modulus == null) {
                throw new InvalidKeyException("modulus == null");
            } else if (privateExponent == null) {
                throw new InvalidKeyException("privateExponent == null");
            }

            try {
                rsa = NativeCrypto.EVP_PKEY_new_RSA(
                        modulus.toByteArray(),
                        null,
                        privateExponent.toByteArray(),
                        null,
                        null);
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Need DSA or RSA private key");
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        // If we had an existing context, destroy it first.
        destroyContextIfExists();
        freeKeysIfExist();

        if (publicKey instanceof DSAPublicKey) {
            try {
                DSAPublicKey dsaPublicKey = (DSAPublicKey)publicKey;
                DSAParams dsaParams = dsaPublicKey.getParams();
                dsa = NativeCrypto.EVP_PKEY_new_DSA(
                        dsaParams.getP().toByteArray(),
                        dsaParams.getQ().toByteArray(),
                        dsaParams.getG().toByteArray(),
                        dsaPublicKey.getY().toByteArray(),
                        null);
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        } else if (publicKey instanceof RSAPublicKey) {
            try {
                RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                rsa = NativeCrypto.EVP_PKEY_new_RSA(
                        rsaPublicKey.getModulus().toByteArray(),
                        rsaPublicKey.getPublicExponent().toByteArray(),
                        null,
                        null,
                        null);
            } catch (Exception e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Need DSA or RSA public key");
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        int handle = (rsa != 0) ? rsa : dsa;

        if (handle == 0) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need DSA or RSA private key");
        }

        try {
            byte[] buffer = new byte[NativeCrypto.EVP_PKEY_size(handle)];
            int bytesWritten = NativeCrypto.EVP_SignFinal(ctx, buffer, 0, handle);

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
        int handle = (rsa != 0) ? rsa : dsa;

        if (handle == 0) {
            // This can't actually happen, but you never know...
            throw new SignatureException("Need DSA or RSA public key");
        }

        try {
            int result = NativeCrypto.EVP_VerifyFinal(ctx, sigBytes, 0, sigBytes.length, handle);
            return result == 1;
        } catch (Exception ex) {
            throw new SignatureException(ex);
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

    private void freeKeysIfExist() {
        if (dsa != 0) {
            NativeCrypto.EVP_PKEY_free(dsa);
        }

        if (rsa != 0) {
            NativeCrypto.EVP_PKEY_free(rsa);
        }
    }

    @Override protected void finalize() throws Throwable {
        try {
            if (dsa != 0) {
                NativeCrypto.EVP_PKEY_free(dsa);
            }

            if (rsa != 0) {
                NativeCrypto.EVP_PKEY_free(rsa);
            }

            if (ctx != 0) {
                NativeCrypto.EVP_MD_CTX_destroy(ctx);
            }
        } finally {
            super.finalize();
        }
    }

    public static final class MD5RSA extends OpenSSLSignature {
        public MD5RSA() throws NoSuchAlgorithmException {
            super("RSA-MD5");
        }
    }
    public static final class SHA1RSA extends OpenSSLSignature {
        public SHA1RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA1");
        }
    }
    public static final class SHA256RSA extends OpenSSLSignature {
        public SHA256RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA256");
        }
    }
    public static final class SHA384RSA extends OpenSSLSignature {
        public SHA384RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA384");
        }
    }
    public static final class SHA512RSA extends OpenSSLSignature {
        public SHA512RSA() throws NoSuchAlgorithmException {
            super("RSA-SHA512");
        }
    }
    public static final class SHA1DSA extends OpenSSLSignature {
        public SHA1DSA() throws NoSuchAlgorithmException {
            super("DSA-SHA1");
        }
    }
}

