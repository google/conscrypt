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

import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Implements the JDK MessageDigest interface using OpenSSL's EVP API.
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
    private String evpAlgorithm;
    
    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private byte[] singleByte = new byte[1];

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     * 
     * @return The new OpenSSLSignature instance.
     * 
     * @throws RuntimeException In case of problems.
     */
    public static OpenSSLSignature getInstance(String algorithm) throws NoSuchAlgorithmException {
        //log("OpenSSLSignature", "getInstance() invoked with " + algorithm);
        return new OpenSSLSignature(algorithm);
    }

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     */
    private OpenSSLSignature(String algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
        
        int i = algorithm.indexOf("with"); 
        if (i == -1) {
            throw new NoSuchAlgorithmException(algorithm);
        }

        // For the special combination of DSA and SHA1, we need to pass the
        // algorithm name as a pair consisting of crypto algorithm and hash
        // algorithm. For all other (RSA) cases, passing the hash algorithm
        // alone is not only sufficient, but actually necessary. OpenSSL
        // doesn't accept something like RSA-SHA1.
        if ("1.3.14.3.2.26with1.2.840.10040.4.1".equals(algorithm)
                || "SHA1withDSA".equals(algorithm)
                || "SHAwithDSA".equals(algorithm)) {
            evpAlgorithm = "DSA-SHA";
        } else {
            evpAlgorithm = algorithm.substring(0, i).replace("-", "").toUpperCase();
        }

        ctx = NativeCrypto.EVP_new();
    }
    
    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (state == SIGN) {
            throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        //log("OpenSSLSignature", "engineInitVerify() invoked with " + publicKey.getClass().getCanonicalName());
        
        if (publicKey instanceof DSAPublicKey) {
            try {
                DSAPublicKey dsaPublicKey = (DSAPublicKey)publicKey;
                DSAParams dsaParams = dsaPublicKey.getParams();
                dsa = NativeCrypto.EVP_PKEY_new_DSA(dsaParams.getP().toByteArray(), 
                        dsaParams.getQ().toByteArray(), dsaParams.getG().toByteArray(),
                        dsaPublicKey.getY().toByteArray(), null);

            } catch (Exception ex) {
                throw new InvalidKeyException(ex.toString());
            }
        } else if (publicKey instanceof RSAPublicKey) {
            try {
                RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                rsa = NativeCrypto.EVP_PKEY_new_RSA(rsaPublicKey.getModulus().toByteArray(),
                        rsaPublicKey.getPublicExponent().toByteArray(), null, null, null);

            } catch (Exception ex) {
                throw new InvalidKeyException(ex.toString());
            }
        } else {
            throw new InvalidKeyException("Need DSA or RSA public key");
        }
        
        try {
            NativeCrypto.EVP_VerifyInit(ctx, evpAlgorithm);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        throw new UnsupportedOperationException();
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
        }
        
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        
        if (dsa != 0) {
            NativeCrypto.EVP_PKEY_free(dsa);
        }

        if (rsa != 0) {
            NativeCrypto.EVP_PKEY_free(rsa);
        }
        
        if (ctx != 0) {
            NativeCrypto.EVP_free(ctx);
        }
    }

    // TODO Just for debugging purposes, remove later.
    private static void log(String tag, String msg) {
        try {
            Class clazz = Class.forName("android.util.Log");
            Method method = clazz.getMethod("d", new Class[] {
                    String.class, String.class
            });
            method.invoke(null, new Object[] {
                    tag, msg
            });
        } catch (Exception ex) {
            // Silently ignore.
        }
    }

}
