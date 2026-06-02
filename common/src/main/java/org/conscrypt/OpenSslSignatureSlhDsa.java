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

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Implements the JDK Signature interface needed for SLH-DSA-SHA2-128S signature generation and
 * verification using BoringSSL.
 */
@Internal
public class OpenSslSignatureSlhDsa extends SignatureSpi {
    /** The current OpenSSL key we're operating on. */
    private OpenSslSlhDsaPrivateKey privateKey;
    private OpenSslSlhDsaPublicKey publicKey;

    /** Buffer to hold value to be signed or verified. */
    private ExposedByteArrayOutputStream buffer = new ExposedByteArrayOutputStream();

    public OpenSslSignatureSlhDsa() {}

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
        this.privateKey = (OpenSslSlhDsaPrivateKey) privateKey;
        this.publicKey = null;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey = (OpenSslSlhDsaPublicKey) publicKey;
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
            // This should not happen.
            throw new SignatureException("No privateKey provided");
        }
        byte[] sig = NativeCrypto.SLHDSA_SHA2_128S_sign(buffer.array(), buffer.size(),
                                                        privateKey.getRaw());
        buffer.reset();
        return sig;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            // This should not happen.
            throw new SignatureException("No publicKey provided");
        }
        int result = NativeCrypto.SLHDSA_SHA2_128S_verify(buffer.array(), buffer.size(), sigBytes,
                                                          publicKey.getRaw());
        buffer.reset();
        return result == 1;
    }
}
