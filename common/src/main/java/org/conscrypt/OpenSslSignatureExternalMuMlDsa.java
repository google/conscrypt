/*
 * Copyright (C) 2026 The Android Open Source Project
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
 * Implements the JDK Signature interface for "external mu" ML-DSA signature generation using
 * BoringSSL.
 *
 * <p>Instead of the message itself, the data passed to {@code update} must be the 64-byte ML-DSA
 * message representative mu of the message (FIPS 204, Algorithm 7, line 6), which the caller
 * computes with an empty context string as {@code SHAKE256-512(tr || 0x00 || 0x00 || message)},
 * where {@code tr = SHAKE256-512(rawPublicKey)} is the hash of the raw encoding of the signer's
 * public key, for example with Conscrypt's {@code "SHAKE256-512"} {@code MessageDigest}. This lets
 * resource-constrained signers delegate the hashing of long messages to another party. Context
 * strings are currently not supported: mu must be computed with an empty context string.
 *
 * <p>The resulting signature is a regular ML-DSA signature of the message, so it is verified with
 * the {@code "ML-DSA"} {@code Signature} and the original message. Verification is therefore not
 * supported by this class: {@code initVerify} and {@code verify} always throw an {@link
 * UnsupportedOperationException}.
 */
@Internal
public abstract class OpenSslSignatureExternalMuMlDsa extends SignatureSpi {
    /** The length in bytes of an ML-DSA message representative mu. */
    private static final int MU_LENGTH = 64;

    private static final OpenSslMlDsaKeyFactory keyFactory = new OpenSslMlDsaKeyFactory.MlDsa();

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Buffer to hold the message representative to be signed.
     */
    private final ExposedByteArrayOutputStream buffer = new ExposedByteArrayOutputStream();

    abstract boolean supportsAlgorithm(MlDsaAlgorithm algorithm);

    /** EXTERNAL-MU-ML-DSA */
    public static class MlDsa extends OpenSslSignatureExternalMuMlDsa {
        public MlDsa() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_44)
                    || algorithm.equals(MlDsaAlgorithm.ML_DSA_65)
                    || algorithm.equals(MlDsaAlgorithm.ML_DSA_87);
        }
    }

    /** EXTERNAL-MU-ML-DSA-44 */
    public static class MlDsa44 extends OpenSslSignatureExternalMuMlDsa {
        public MlDsa44() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_44);
        }
    }

    /** EXTERNAL-MU-ML-DSA-65 */
    public static class MlDsa65 extends OpenSslSignatureExternalMuMlDsa {
        public MlDsa65() {
            super();
        }
        @Override
        boolean supportsAlgorithm(MlDsaAlgorithm algorithm) {
            return algorithm.equals(MlDsaAlgorithm.ML_DSA_65);
        }
    }

    /** EXTERNAL-MU-ML-DSA-87 */
    public static class MlDsa87 extends OpenSslSignatureExternalMuMlDsa {
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
    // engineGetParameter is deprecated in SignatureSpi, but abstract, so it must be implemented.
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        OpenSslMlDsaPrivateKey conscryptPrivateKey =
                (OpenSslMlDsaPrivateKey) keyFactory.engineTranslateKey(privateKey);
        MlDsaAlgorithm algorithm = conscryptPrivateKey.getMlDsaAlgorithm();
        if (!supportsAlgorithm(algorithm)) {
            throw new InvalidKeyException("Key version mismatch: " + algorithm);
        }
        OpenSSLKey keyLocal = conscryptPrivateKey.getOpenSSLKey();
        if (keyLocal == null) {
            throw new InvalidKeyException("Key is destroyed");
        }
        this.key = keyLocal;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException(
                "EXTERNAL-MU-ML-DSA does not support verification. Verify the signature with "
                + "ML-DSA and the original message.");
    }

    @Override
    // engineSetParameter is deprecated in SignatureSpi, but abstract, so it must be implemented.
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (key == null) {
            throw new SignatureException("No key provided");
        }
        if (buffer.size() != MU_LENGTH) {
            buffer.reset();
            throw new SignatureException("The input must be the " + MU_LENGTH
                                         + "-byte ML-DSA message representative mu");
        }
        byte[] mu = buffer.toByteArray();
        buffer.reset();
        try {
            return NativeCrypto.MLDSA_sign_message_representative(key.getNativeRef(), mu);
        } catch (InvalidKeyException e) {
            // Cannot happen, since engineInitSign only accepts ML-DSA private keys.
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        throw new UnsupportedOperationException(
                "EXTERNAL-MU-ML-DSA does not support verification. Verify the signature with "
                + "ML-DSA and the original message.");
    }
}
