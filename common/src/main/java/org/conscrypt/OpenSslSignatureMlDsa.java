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
 * Implements the JDK Signature interface needed for ML-DSA signature generation and verification
 * using BoringSSL.
 */
@Internal
public abstract class OpenSslSignatureMlDsa extends SignatureSpi {
    /**
     * The current OpenSSL key we're operating on.
     */

    private OpenSSLKey key;
    private NativeRef.EVP_MD_CTX ctx;

    /**
     * Buffer to hold value to be signed or verified.
     */
    private ExposedByteArrayOutputStream buffer = new ExposedByteArrayOutputStream();

    abstract boolean supportsAlgorithm(MlDsaAlgorithm algorithm);

    /** ML-DSA */
    public static class MlDsa extends OpenSslSignatureMlDsa {
        public MlDsa() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_65)
                    || algorithm.equals(MlDsaAlgorithm.ML_DSA_87);
        }
    }

    /** ML-DSA-65 */
    public static class MlDsa65 extends OpenSslSignatureMlDsa {
        public MlDsa65() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_65);
        }
    }

    /** ML-DSA-87 */
    public static class MlDsa87 extends OpenSslSignatureMlDsa {
        public MlDsa87() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_87);
        }
    }

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
        key = OpenSSLKey.fromPrivateKey(privateKey);
        MlDsaAlgorithm algorithm = OpenSslMlDsaKeyFactory.getMlDsaAlgorithm(key);
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeyException("Key version mismatch: " + algorithm);
        }
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_DigestSignInit(ctxLocal, 0, key.getNativeRef());
        this.ctx = ctxLocal;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        key = OpenSSLKey.fromPublicKey(publicKey);
        MlDsaAlgorithm algorithm = OpenSslMlDsaKeyFactory.getMlDsaAlgorithm(key);
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeyException("Key version mismatch: " + algorithm);
        }
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        NativeCrypto.EVP_DigestVerifyInit(ctxLocal, 0, key.getNativeRef());
        this.ctx = ctxLocal;
        buffer.reset();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (key == null) {
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
