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

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

/**
 * An implementation of {@link javax.crypto.Mac} which uses BoringSSL to perform all the operations.
 */
@Internal
public abstract class OpenSSLMac extends MacSpi {
    private NativeRef.HMAC_CTX ctx;

    /**
     * Holds the EVP_MD for the hashing algorithm, e.g.
     * EVP_get_digestbyname("sha1");
     */
    private final long evp_md;

    /**
     * The secret key used in this keyed MAC.
     */
    private byte[] keyBytes;

    /**
     * Holds the output size of the message digest.
     */
    private final int size;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    private OpenSSLMac(long evp_md, int size) {
        this.evp_md = evp_md;
        this.size = size;
    }

    @Override
    protected int engineGetMacLength() {
        return size;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("key must be a SecretKey");
        }

        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown parameter type");
        }

        keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("key cannot be encoded");
        }

        resetContext();
    }

    private final void resetContext() {
        NativeRef.HMAC_CTX ctxLocal = new NativeRef.HMAC_CTX(NativeCrypto.HMAC_CTX_new());
        if (keyBytes != null) {
            NativeCrypto.HMAC_Init_ex(ctxLocal, keyBytes, evp_md);
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
        final NativeRef.HMAC_CTX ctxLocal = ctx;
        NativeCrypto.HMAC_Update(ctxLocal, input, offset, len);
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

        // MAC the contents between Buffer's position and limit (remaining() number of bytes)
        int position = input.position();
        if (position < 0) {
            throw new RuntimeException("Negative position");
        }
        long ptr = baseAddress + position;
        int len = input.remaining();
        if (len < 0) {
            throw new RuntimeException("Negative remaining amount");
        }

        final NativeRef.HMAC_CTX ctxLocal = ctx;
        NativeCrypto.HMAC_UpdateDirect(ctxLocal, ptr, len);
        input.position(position + len);
    }

    @Override
    protected byte[] engineDoFinal() {
        final NativeRef.HMAC_CTX ctxLocal = ctx;
        final byte[] output = NativeCrypto.HMAC_Final(ctxLocal);
        resetContext();
        return output;
    }

    @Override
    protected void engineReset() {
        resetContext();
    }

    public static final class HmacMD5 extends OpenSSLMac {
        public HmacMD5() {
            super(EvpMdRef.MD5.EVP_MD, EvpMdRef.MD5.SIZE_BYTES);
        }
    }

    public static final class HmacSHA1 extends OpenSSLMac {
        public HmacSHA1() {
            super(EvpMdRef.SHA1.EVP_MD, EvpMdRef.SHA1.SIZE_BYTES);
        }
    }

    public static final class HmacSHA224 extends OpenSSLMac {
        public HmacSHA224() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA224.EVP_MD, EvpMdRef.SHA224.SIZE_BYTES);
        }
    }

    public static final class HmacSHA256 extends OpenSSLMac {
        public HmacSHA256() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA256.EVP_MD, EvpMdRef.SHA256.SIZE_BYTES);
        }
    }

    public static final class HmacSHA384 extends OpenSSLMac {
        public HmacSHA384() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA384.EVP_MD, EvpMdRef.SHA384.SIZE_BYTES);
        }
    }

    public static final class HmacSHA512 extends OpenSSLMac {
        public HmacSHA512() {
            super(EvpMdRef.SHA512.EVP_MD, EvpMdRef.SHA512.SIZE_BYTES);
        }
    }
}
