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
    private boolean digestInitializedInContext;

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm name.
     */
    private OpenSSLMessageDigestJDK(long evp_md, int size) throws NoSuchAlgorithmException {
        this.evp_md = evp_md;
        this.size = size;
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        this.ctx = ctxLocal;
    }

    private OpenSSLMessageDigestJDK(long evp_md, int size, NativeRef.EVP_MD_CTX ctx,
            boolean digestInitializedInContext) {
        this.evp_md = evp_md;
        this.size = size;
        this.ctx = ctx;
        this.digestInitializedInContext = digestInitializedInContext;
    }

    private void ensureDigestInitializedInContext() {
        if (!digestInitializedInContext) {
            final NativeRef.EVP_MD_CTX ctxLocal = ctx;
            NativeCrypto.EVP_DigestInit_ex(ctxLocal, evp_md);
            digestInitializedInContext = true;
        }
    }

    @Override
    protected void engineReset() {
        // Reset to the same state as at the end of the <init>(long evp_md, int size). We can avoid
        // allocating a new EVP_MD_CTX by invoking EVP_MD_CTX_cleanup on the existing one.
        // EVP_MD_CTX_cleanup cleans up and reinitializes the EVP_MD_CTX.
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        NativeCrypto.EVP_MD_CTX_cleanup(ctxLocal);
        digestInitializedInContext = false;
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
        if (position < 0) {
            throw new RuntimeException("Negative position");
        }
        long ptr = baseAddress + position;
        int len = input.remaining();
        if (len < 0) {
            throw new RuntimeException("Negative remaining amount");
        }

        ensureDigestInitializedInContext();
        NativeCrypto.EVP_DigestUpdateDirect(ctx, ptr, len);
        input.position(position + len);
    }

    @Override
    protected byte[] engineDigest() {
        ensureDigestInitializedInContext();
        final byte[] result = new byte[size];
        NativeCrypto.EVP_DigestFinal_ex(ctx, result, 0);

        // Optimized reset path:
        // 1. No need to wipe EVP_MD_CTX because EVP_DigestFinal_ex has already cleansed any
        //    sensitive state from it.
        // 2. Require EVP_DigestInit_ex to be invoked before this MessageDigestSpi starts computing
        //    a new digest.
        digestInitializedInContext = false;

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
        // EVP_MD_CTX_copy_ex requires that the digest struct of source EVP_MD_CTX is initialized.
        // There's no need to invoke EVP_MD_CTX_copy_ex when the digest struct isn't initialized.
        if (digestInitializedInContext) {
            NativeCrypto.EVP_MD_CTX_copy_ex(ctxCopy, ctx);
        }
        return new OpenSSLMessageDigestJDK(evp_md, size, ctxCopy, digestInitializedInContext);
    }
}
