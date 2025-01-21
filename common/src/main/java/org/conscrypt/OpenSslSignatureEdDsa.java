/*
 * Copyright 2025 The Android Open Source Project
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

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Implements the JDK Signature interface needed for EdDSA signature generation and verification
 * using BoringSSL.
 */
@Internal
public class OpenSslSignatureEdDsa extends SignatureSpi {
    private NativeRef.EVP_MD_CTX ctx;

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    // Buffer provides access to the underlying byte array without making a copy.
    private static final class Buffer extends ByteArrayOutputStream {
        byte[] array() {
            return buf;
        }
    }

    /**
     * buffer to hold value to be signed or verified.
     */
    private Buffer buffer = new Buffer();

    public OpenSslSignatureEdDsa() {}

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private static OpenSSLKey verifyKey(OpenSSLKey key) throws InvalidKeyException {
        int pkeyType = NativeCrypto.EVP_PKEY_type(key.getNativeRef());
        if (pkeyType != NativeConstants.EVP_PKEY_ED25519) {
            throw new InvalidKeyException("Non-ED25519 key used to initialize ED25519 signature.");
        }
        return key;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        key = verifyKey(OpenSSLKey.fromPrivateKey(privateKey));
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_DigestSignInit(ctxLocal, 0, key.getNativeRef());
        this.ctx = ctxLocal;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        key = verifyKey(OpenSSLKey.fromPublicKey(publicKey));
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_DigestVerifyInit(ctxLocal, 0, key.getNativeRef());
        this.ctx = ctxLocal;
    }

    @Override
    @SuppressWarnings("deprecation") // We are required to implement this method.
    protected void engineSetParameter(String param, Object value) {}

    @Override
    protected byte[] engineSign() throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No key provided");
        }
        byte[] sig = NativeCrypto.EVP_DigestSign(ctxLocal, buffer.array(), 0, buffer.size());
        buffer.reset();
        return sig;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No key provided");
        }

        boolean result = NativeCrypto.EVP_DigestVerify(
                ctxLocal, sigBytes, 0, sigBytes.length, buffer.array(), 0, buffer.size());
        buffer.reset();
        return result;
    }
}
