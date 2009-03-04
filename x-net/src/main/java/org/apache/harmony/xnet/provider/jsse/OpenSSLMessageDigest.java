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

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * Implements the BouncyCastle Digest interface using OpenSSL's EVP API.
 */
public class OpenSSLMessageDigest implements ExtendedDigest {

    /**
     * Holds the name of the hashing algorithm, e.g. "SHA-1";
     */
    private String algorithm;

    /**
     * Holds a pointer to the native message digest context.
     */
    private int ctx;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private byte[] singleByte = new byte[1];

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm
     * name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     * 
     * @return The new OpenSSLMessageDigest instance.
     * 
     * @throws RuntimeException In case of problems.
     */
    public static OpenSSLMessageDigest getInstance(String algorithm) {
        return new OpenSSLMessageDigest(algorithm);
    }

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm
     * name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     */
    private OpenSSLMessageDigest(String algorithm) {
        this.algorithm = algorithm;
        ctx = NativeCrypto.EVP_new();
        try {
            NativeCrypto.EVP_DigestInit(ctx, algorithm.replace("-", "").toLowerCase());
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage() + " (" + algorithm + ")");
        }
    }
    
    public int doFinal(byte[] out, int outOff) {
        int i = NativeCrypto.EVP_DigestFinal(ctx, out, outOff);
        reset();
        return i;
    }

    public String getAlgorithmName() {
        return algorithm;
    }

    public int getDigestSize() {
        return NativeCrypto.EVP_DigestSize(ctx);
    }

    public int getByteLength() {
        return NativeCrypto.EVP_DigestBlockSize(ctx);
    }

    public void reset() {
        NativeCrypto.EVP_DigestInit(ctx, algorithm.replace("-", "").toLowerCase());
    }

    public void update(byte in) {
        singleByte[0] = in;
        NativeCrypto.EVP_DigestUpdate(ctx, singleByte, 0, 1);
    }

    public void update(byte[] in, int inOff, int len) {
        NativeCrypto.EVP_DigestUpdate(ctx, in, inOff, len);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        NativeCrypto.EVP_free(ctx);
    }
    
}
