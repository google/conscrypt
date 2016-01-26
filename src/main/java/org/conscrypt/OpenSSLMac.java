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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

public abstract class OpenSSLMac extends MacSpi {
    private NativeRef.EVP_MD_CTX ctx;

    /**
     * Holds the EVP_MD for the hashing algorithm, e.g.
     * EVP_get_digestbyname("sha1");
     */
    private final long evp_md;

    /**
     * The key type of the secret key.
     */
    private final int evp_pkey_type;

    /**
     * The secret key used in this keyed MAC.
     */
    private OpenSSLKey macKey;

    /**
     * Holds the output size of the message digest.
     */
    private final int size;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    private OpenSSLMac(long evp_md, int size, int evp_pkey_type) {
        this.evp_md = evp_md;
        this.size = size;
        this.evp_pkey_type = evp_pkey_type;
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

        if (key instanceof OpenSSLKeyHolder) {
            macKey = ((OpenSSLKeyHolder) key).getOpenSSLKey();
        } else {
            final byte[] keyBytes = key.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("key cannot be encoded");
            }

            macKey = new OpenSSLKey(NativeCrypto.EVP_PKEY_new_mac_key(evp_pkey_type, keyBytes));
        }

        resetContext();
    }

    private final void resetContext() {
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_MD_CTX_init(ctxLocal);

        final OpenSSLKey macKey = this.macKey;
        if (macKey != null) {
            NativeCrypto.EVP_DigestSignInit(ctxLocal, evp_md, macKey.getNativeRef());
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
        NativeCrypto.EVP_DigestUpdate(ctxLocal, input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        final byte[] output = NativeCrypto.EVP_DigestSignFinal(ctxLocal);
        resetContext();
        return output;
    }

    @Override
    protected void engineReset() {
        resetContext();
    }

    public static class HmacMD5 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("md5");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacMD5() {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }

    public static class HmacSHA1 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha1");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacSHA1() {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }

    public static class HmacSHA224 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha224");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacSHA224() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }

    public static class HmacSHA256 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha256");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacSHA256() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }

    public static class HmacSHA384 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha384");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacSHA384() throws NoSuchAlgorithmException {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }

    public static class HmacSHA512 extends OpenSSLMac {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha512");
        private static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);

        public HmacSHA512() {
            super(EVP_MD, SIZE, NativeConstants.EVP_PKEY_HMAC);
        }
    }
}
