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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implements the JDK MessageDigest interface using OpenSSL's EVP API.
 */
public class OpenSSLMessageDigestJDK extends MessageDigest implements Cloneable {

    /**
     * Holds a pointer to the native message digest context.
     */
    private int ctx;

    /**
     * The OpenSSL version of the algorithm name for later use by reset.
     */
    private final String openssl;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm
     * name.
     *
     * @param algorithm The standard name of the algorithm, e.g. "SHA-1".
     * @param algorithm The name of the openssl algorithm, e.g. "sha1".
     */
    private OpenSSLMessageDigestJDK(String algorithm, String openssl)
            throws NoSuchAlgorithmException {
        super(algorithm);
        this.openssl = openssl;

        ctx = NativeCrypto.EVP_MD_CTX_create();
        try {
            NativeCrypto.EVP_DigestInit(ctx, openssl);
        } catch (Exception ex) {
            throw new NoSuchAlgorithmException(ex.getMessage() + " (" + algorithm + ")");
        }
    }

    @Override
    protected byte[] engineDigest() {
        byte[] result = new byte[NativeCrypto.EVP_MD_CTX_size(ctx)];
        NativeCrypto.EVP_DigestFinal(ctx, result, 0);
        NativeCrypto.EVP_DigestInit(ctx, openssl);
        return result;
    }

    @Override
    protected void engineReset() {
        NativeCrypto.EVP_DigestInit(ctx, openssl);
    }

    @Override
    protected int engineGetDigestLength() {
        return NativeCrypto.EVP_MD_CTX_size(ctx);
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        NativeCrypto.EVP_DigestUpdate(ctx, input, offset, len);
    }

    public Object clone() throws CloneNotSupportedException {
        OpenSSLMessageDigestJDK d = (OpenSSLMessageDigestJDK) super.clone();
        d.ctx = NativeCrypto.EVP_MD_CTX_copy(ctx);
        return d;
    }

    @Override protected void finalize() throws Throwable {
        try {
            NativeCrypto.EVP_MD_CTX_destroy(ctx);
            ctx = 0;
        } finally {
            super.finalize();
        }
    }

    public static class MD5 extends OpenSSLMessageDigestJDK {
        public MD5() throws NoSuchAlgorithmException {
            super("MD5", "md5");
        }
    }

    public static class SHA1 extends OpenSSLMessageDigestJDK {
        public SHA1() throws NoSuchAlgorithmException {
            super("SHA-1", "sha1");
        }
    }

    public static class SHA256 extends OpenSSLMessageDigestJDK {
        public SHA256() throws NoSuchAlgorithmException {
            super("SHA-256", "sha256");
        }
    }

    public static class SHA384 extends OpenSSLMessageDigestJDK {
        public SHA384() throws NoSuchAlgorithmException {
            super("SHA-384", "sha384");
        }
    }

    public static class SHA512 extends OpenSSLMessageDigestJDK {
        public SHA512() throws NoSuchAlgorithmException {
            super("SHA-512", "sha512");
        }
    }
}
