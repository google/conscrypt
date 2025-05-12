/*
 * Copyright (C) 2025 The Android Open Source Project
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
 * Implements the JDK Signature interface needed for ML-DSA signature generation and verification
 * using BoringSSL.
 */
@Internal
public class OpenSslSignatureMlDsa extends SignatureSpi {
    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSslMlDsaPrivateKey privateKey;
    private OpenSslMlDsaPublicKey publicKey;

    /**
     * Buffer to hold value to be signed or verified.
     */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public OpenSslSignatureMlDsa() {}

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

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = (OpenSslMlDsaPrivateKey) privateKey;
        this.publicKey = null;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey = (OpenSslMlDsaPublicKey) publicKey;
        this.privateKey = null;
        buffer.reset();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No privateKey provided");
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();
        return NativeCrypto.MLDSA65_sign(data, privateKey.getSeed());
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No publicKey provided");
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();
        int result = NativeCrypto.MLDSA65_verify(data, sigBytes, publicKey.getRaw());
        return result == 1;
    }
}
