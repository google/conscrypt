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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

/**
 * An implementation of {@link java.security.PrivateKey} for RSA keys which uses BoringSSL to
 * perform all the operations.
 */
final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAPrivateCrtKey {
    private static final long serialVersionUID = 3785291944868707197L;

    private BigInteger publicExponent;

    private BigInteger primeP;

    private BigInteger primeQ;

    private BigInteger primeExponentP;

    private BigInteger primeExponentQ;

    private BigInteger crtCoefficient;

    OpenSSLRSAPrivateCrtKey(OpenSSLKey key) {
        super(key);
    }

    OpenSSLRSAPrivateCrtKey(OpenSSLKey key, byte[][] params) {
        super(key, params);
    }

    OpenSSLRSAPrivateCrtKey(RSAPrivateCrtKeySpec rsaKeySpec) throws InvalidKeySpecException {
        super(init(rsaKeySpec));
    }

    private static OpenSSLKey init(RSAPrivateCrtKeySpec rsaKeySpec) throws InvalidKeySpecException {
        BigInteger modulus = rsaKeySpec.getModulus();
        BigInteger privateExponent = rsaKeySpec.getPrivateExponent();

        if (modulus == null) {
            throw new InvalidKeySpecException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeySpecException("privateExponent == null");
        }

        try {
            /*
             * OpenSSL uses the public modulus to do RSA blinding. If
             * the public modulus is not available, the call to
             * EVP_PKEY_new_RSA will turn off blinding for this key
             * instance.
             */
            final BigInteger publicExponent = rsaKeySpec.getPublicExponent();
            final BigInteger primeP = rsaKeySpec.getPrimeP();
            final BigInteger primeQ = rsaKeySpec.getPrimeQ();
            final BigInteger primeExponentP = rsaKeySpec.getPrimeExponentP();
            final BigInteger primeExponentQ = rsaKeySpec.getPrimeExponentQ();
            final BigInteger crtCoefficient = rsaKeySpec.getCrtCoefficient();

            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                    modulus.toByteArray(),
                    publicExponent == null ? null : publicExponent.toByteArray(),
                    privateExponent.toByteArray(),
                    primeP == null ? null : primeP.toByteArray(),
                    primeQ == null ? null : primeQ.toByteArray(),
                    primeExponentP == null ? null : primeExponentP.toByteArray(),
                    primeExponentQ == null ? null : primeExponentQ.toByteArray(),
                    crtCoefficient == null ? null : crtCoefficient.toByteArray()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    static OpenSSLKey getInstance(RSAPrivateCrtKey rsaPrivateKey) throws InvalidKeyException {
        /*
         * If the key is not encodable (PKCS11-like key), then wrap it and use
         * JNI upcalls to satisfy requests.
         */
        if (rsaPrivateKey.getFormat() == null) {
            return wrapPlatformKey(rsaPrivateKey);
        }

        BigInteger modulus = rsaPrivateKey.getModulus();
        BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();

        if (modulus == null) {
            throw new InvalidKeyException("modulus == null");
        } else if (privateExponent == null) {
            throw new InvalidKeyException("privateExponent == null");
        }

        try {
            /*
             * OpenSSL uses the public modulus to do RSA blinding. If
             * the public modulus is not available, the call to
             * EVP_PKEY_new_RSA will turn off blinding for this key
             * instance.
             */
            final BigInteger publicExponent = rsaPrivateKey.getPublicExponent();
            final BigInteger primeP = rsaPrivateKey.getPrimeP();
            final BigInteger primeQ = rsaPrivateKey.getPrimeQ();
            final BigInteger primeExponentP = rsaPrivateKey.getPrimeExponentP();
            final BigInteger primeExponentQ = rsaPrivateKey.getPrimeExponentQ();
            final BigInteger crtCoefficient = rsaPrivateKey.getCrtCoefficient();

            return new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                    modulus.toByteArray(),
                    publicExponent == null ? null : publicExponent.toByteArray(),
                    privateExponent.toByteArray(),
                    primeP == null ? null : primeP.toByteArray(),
                    primeQ == null ? null : primeQ.toByteArray(),
                    primeExponentP == null ? null : primeExponentP.toByteArray(),
                    primeExponentQ == null ? null : primeExponentQ.toByteArray(),
                    crtCoefficient == null ? null : crtCoefficient.toByteArray()));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    synchronized void readParams(byte[][] params) {
        super.readParams(params);
        // params[0] read in super.readParams
        if (params[1] != null) {
            publicExponent = new BigInteger(params[1]);
        }
        // params[2] read in super.readParams
        if (params[3] != null) {
            primeP = new BigInteger(params[3]);
        }
        if (params[4] != null) {
            primeQ = new BigInteger(params[4]);
        }
        if (params[5] != null) {
            primeExponentP = new BigInteger(params[5]);
        }
        if (params[6] != null) {
            primeExponentQ = new BigInteger(params[6]);
        }
        if (params[7] != null) {
            crtCoefficient = new BigInteger(params[7]);
        }
    }

    @Override
    public BigInteger getPublicExponent() {
        ensureReadParams();
        return publicExponent;
    }

    @Override
    public BigInteger getPrimeP() {
        ensureReadParams();
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        ensureReadParams();
        return primeQ;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        ensureReadParams();
        return primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        ensureReadParams();
        return primeExponentQ;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        ensureReadParams();
        return crtCoefficient;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof OpenSSLRSAPrivateKey) {
            OpenSSLRSAPrivateKey other = (OpenSSLRSAPrivateKey) o;
            return getOpenSSLKey().equals(other.getOpenSSLKey());
        }

        if (o instanceof RSAPrivateCrtKey) {
            ensureReadParams();
            RSAPrivateCrtKey other = (RSAPrivateCrtKey) o;

            if (getOpenSSLKey().isHardwareBacked()) {
                return getModulus().equals(other.getModulus())
                        && publicExponent.equals(other.getPublicExponent());
            } else {
                return getModulus().equals(other.getModulus())
                        && publicExponent.equals(other.getPublicExponent())
                        && getPrivateExponent().equals(other.getPrivateExponent())
                        && primeP.equals(other.getPrimeP()) && primeQ.equals(other.getPrimeQ())
                        && primeExponentP.equals(other.getPrimeExponentP())
                        && primeExponentQ.equals(other.getPrimeExponentQ())
                        && crtCoefficient.equals(other.getCrtCoefficient());
            }
        } else if (o instanceof RSAPrivateKey) {
            ensureReadParams();
            RSAPrivateKey other = (RSAPrivateKey) o;

            if (getOpenSSLKey().isHardwareBacked()) {
                return getModulus().equals(other.getModulus());
            } else {
                return getModulus().equals(other.getModulus())
                        && getPrivateExponent().equals(other.getPrivateExponent());
            }
        }

        return false;
    }

    @Override
    public int hashCode() {
        int hashCode = super.hashCode();
        if (publicExponent != null) {
            hashCode ^= publicExponent.hashCode();
        }
        return hashCode;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("OpenSSLRSAPrivateCrtKey{");

        ensureReadParams();
        sb.append("modulus=");
        sb.append(getModulus().toString(16));

        if (publicExponent != null) {
            sb.append(',');
            sb.append("publicExponent=");
            sb.append(publicExponent.toString(16));
        }

        sb.append('}');
        return sb.toString();
    }

    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();

        key = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_RSA(
                modulus.toByteArray(),
                publicExponent == null ? null : publicExponent.toByteArray(),
                privateExponent.toByteArray(),
                primeP == null ? null : primeP.toByteArray(),
                primeQ == null ? null : primeQ.toByteArray(),
                primeExponentP == null ? null : primeExponentP.toByteArray(),
                primeExponentQ == null ? null : primeExponentQ.toByteArray(),
                crtCoefficient == null ? null : crtCoefficient.toByteArray()));
        fetchedParams = true;
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        if (getOpenSSLKey().isHardwareBacked()) {
            throw new NotSerializableException("Hardware backed keys cannot be serialized");
        }

        ensureReadParams();
        stream.defaultWriteObject();
    }
}
