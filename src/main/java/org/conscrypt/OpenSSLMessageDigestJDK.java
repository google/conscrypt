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

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

/**
 * Implements the JDK MessageDigest interface using OpenSSL's EVP API.
 */
public class OpenSSLMessageDigestJDK extends MessageDigestSpi implements Cloneable {
    private final NativeRef.EVP_MD_CTX ctx;

    /**
     * Holds the EVP_MD for the hashing algorithm, e.g. EVP_get_digestbyname("sha1");
     */
    private final long evp_md;

    /**
     * Holds the output size of the message digest.
     */
    private final int size;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * Whether the digest struct has been initialized inside EVP_MD_CTX.
     */
    private boolean mDigestInitializedInContext;

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm name.
     */
    private OpenSSLMessageDigestJDK(long evp_md, int size) throws NoSuchAlgorithmException {
        this.evp_md = evp_md;
        this.size = size;
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_MD_CTX_init(ctxLocal);
        this.ctx = ctxLocal;
    }

    private OpenSSLMessageDigestJDK(long evp_md, int size, NativeRef.EVP_MD_CTX ctx,
            boolean digestInitializedInContext) {
        this.evp_md = evp_md;
        this.size = size;
        this.ctx = ctx;
        this.mDigestInitializedInContext = digestInitializedInContext;
    }

    private void ensureDigestInitializedInContext() {
        if (!mDigestInitializedInContext) {
            final NativeRef.EVP_MD_CTX ctxLocal = ctx;
	    NativeCrypto.EVP_DigestInit(ctxLocal, evp_md);
            mDigestInitializedInContext = true;
        }
    }

    @Override
    protected void engineReset() {
        mDigestInitializedInContext = false;
    }

    @Override
    protected int engineGetDigestLength() {
        return size;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        ensureDigestInitializedInContext();
        NativeCrypto.EVP_DigestUpdate(ctx, input, offset, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        // Optimization: Avoid copying/allocation for direct buffers because their contents are
        // stored as a contiguous region in memory and thus can be efficiently accessed from native
        // code.

        if (!input.hasRemaining()) {
            return;
        }

        if (!input.isDirect()) {
            super.engineUpdate(input);
            return;
        }

        long baseAddress = NativeCrypto.getDirectBufferAddress(input);
        if (baseAddress == 0) {
            // Direct buffer's contents can't be accessed from JNI  -- superclass's implementation
            // is good enough to handle this.
            super.engineUpdate(input);
            return;
        }

        // Digest the contents between Buffer's position and limit (remaining() number of bytes)
        int position = input.position();
        long ptr = baseAddress + position;
        if (ptr < baseAddress) {
            throw new RuntimeException("Start pointer overflow");
        }

        int len = input.remaining();
        if (ptr + len < ptr) {
            throw new RuntimeException("End pointer overflow");
        }

        ensureDigestInitializedInContext();
        NativeCrypto.EVP_DigestUpdateDirect(ctx, ptr, len);
        input.position(position + len);
    }

    @Override
    protected byte[] engineDigest() {
        ensureDigestInitializedInContext();
        final byte[] result = new byte[size];
        NativeCrypto.EVP_DigestFinal(ctx, result, 0);
        mDigestInitializedInContext = false;
        return result;
    }

    public static class MD5 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("md5");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public MD5() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    public static class SHA1 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha1");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public SHA1() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    public static class SHA224 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha224");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public SHA224() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    public static class SHA256 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha256");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public SHA256() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    public static class SHA384 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha384");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public SHA384() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    public static class SHA512 extends OpenSSLMessageDigestJDK {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha512");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
        public SHA512() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE);
        }
    }

    @Override
    public Object clone() {
        NativeRef.EVP_MD_CTX ctxCopy = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_MD_CTX_init(ctxCopy);
        NativeCrypto.EVP_MD_CTX_copy(ctxCopy, ctx);
        return new OpenSSLMessageDigestJDK(evp_md, size, ctxCopy, mDigestInitializedInContext);
    }
}
