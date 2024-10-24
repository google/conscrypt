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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Implements the subset of the JDK Signature interface needed for
 * signature verification using OpenSSL.
 */
@Internal
public class OpenSSLSignature extends SignatureSpi {
    private enum EngineType {
        RSA, EC,
    }

    private NativeRef.EVP_MD_CTX ctx;

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Holds the type of the Java algorithm.
     */
    private final EngineType engineType;

    /**
     * Digest algorithm (reference to {@code EVP_MD}).
     */
    private final long evpMdRef;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * True when engine is initialized to signing.
     */
    private boolean signing;

    /**
     * Public key algorithm context (reference to {@code EVP_PKEY_CTX}).
     */
    private long evpPkeyCtx;

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *
     * @param evpMdRef digest algorithm ({@code EVP_MD} reference).
     */
    private OpenSSLSignature(long evpMdRef, EngineType engineType) {
        this.engineType = engineType;
        this.evpMdRef = evpMdRef;
    }

    private void resetContext() throws InvalidAlgorithmParameterException {
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        if (signing) {
            evpPkeyCtx = NativeCrypto.EVP_DigestSignInit(ctxLocal, evpMdRef, key.getNativeRef());
        } else {
            evpPkeyCtx = NativeCrypto.EVP_DigestVerifyInit(ctxLocal, evpMdRef, key.getNativeRef());
        }
        configureEVP_PKEY_CTX(evpPkeyCtx);
        this.ctx = ctxLocal;
    }

    /**
     * Configures the public key algorithm context ({@code EVP_PKEY_CTX}) associated with this
     * operation.
     *
     * <p>The default implementation does nothing.
     *
     * @param ctx reference to the context ({@code EVP_PKEY_CTX}).
     */
    protected void configureEVP_PKEY_CTX(long ctx) throws InvalidAlgorithmParameterException {}

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (signing) {
            NativeCrypto.EVP_DigestSignUpdate(ctxLocal, input, offset, len);
        } else {
            NativeCrypto.EVP_DigestVerifyUpdate(ctxLocal, input, offset, len);
        }
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

        // Process the contents between Buffer's position and limit (remaining() number of bytes)
        int position = input.position();
        if (position < 0) {
            throw new RuntimeException("Negative position");
        }
        long ptr = baseAddress + position;
        int len = input.remaining();
        if (len < 0) {
            throw new RuntimeException("Negative remaining amount");
        }

        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (signing) {
            NativeCrypto.EVP_DigestSignUpdateDirect(ctxLocal, ptr, len);
        } else {
            NativeCrypto.EVP_DigestVerifyUpdateDirect(ctxLocal, ptr, len);
        }
        input.position(position + len);
    }

    @Deprecated
    @Override
    @SuppressWarnings("InlineMeSuggester")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private void checkEngineType(OpenSSLKey pkey) throws InvalidKeyException {
        final int pkeyType = NativeCrypto.EVP_PKEY_type(pkey.getNativeRef());

        switch (engineType) {
            case RSA:
                if (pkeyType != NativeConstants.EVP_PKEY_RSA) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not RSA)");
                }
                break;
            case EC:
                if (pkeyType != NativeConstants.EVP_PKEY_EC) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not EC)");
                }
                break;
            default:
                throw new InvalidKeyException("Key must be of type " + engineType);
        }
    }

    private void initInternal(OpenSSLKey newKey, boolean signing) throws InvalidKeyException {
        checkEngineType(newKey);
        key = newKey;

        this.signing = signing;
        try {
            resetContext();
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPrivateKey(privateKey), true);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPublicKey(publicKey), false);
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    @SuppressWarnings("Finally")
    protected byte[] engineSign() throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        try {
            return NativeCrypto.EVP_DigestSignFinal(ctxLocal);
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after sign
             * calls.
             */
            try {
                resetContext();
            } catch (InvalidAlgorithmParameterException e) {
                throw new AssertionError("Reset of context failed after it was successful once");
            }
        }
    }

    @Override
    @SuppressWarnings("Finally")
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        try {
            return NativeCrypto.EVP_DigestVerifyFinal(ctxLocal, sigBytes, 0, sigBytes.length);
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after
             * verify calls.
             */
            try {
                resetContext();
            } catch (InvalidAlgorithmParameterException e) {
                throw new AssertionError("Reset of context failed after it was successful once");
            }
        }
    }

    /**
     * Returns the public key algorithm context ({@code EVP_PKEY_CTX} reference) associated with
     * this operation or {@code 0} if operation hasn't been initialized.
     */
    protected final long getEVP_PKEY_CTX() {
        return evpPkeyCtx;
    }

    /**
     * Base class for {@code RSASSA-PKCS1-v1_5} signatures.
     */
    abstract static class RSAPKCS1Padding extends OpenSSLSignature {
        RSAPKCS1Padding(long evpMdRef) {
            super(evpMdRef, EngineType.RSA);
        }

        @Override
        protected final void configureEVP_PKEY_CTX(long ctx)
                throws InvalidAlgorithmParameterException {
            NativeCrypto.EVP_PKEY_CTX_set_rsa_padding(ctx, NativeConstants.RSA_PKCS1_PADDING);
        }
    }

    public static final class MD5RSA extends RSAPKCS1Padding {
        public MD5RSA() {
            super(EvpMdRef.MD5.EVP_MD);
        }
    }
    public static final class SHA1RSA extends RSAPKCS1Padding {
        public SHA1RSA() {
            super(EvpMdRef.SHA1.EVP_MD);
        }
    }
    public static final class SHA224RSA extends RSAPKCS1Padding {
        public SHA224RSA() {
            super(EvpMdRef.SHA224.EVP_MD);
        }
    }
    public static final class SHA256RSA extends RSAPKCS1Padding {
        public SHA256RSA() {
            super(EvpMdRef.SHA256.EVP_MD);
        }
    }
    public static final class SHA384RSA extends RSAPKCS1Padding {
        public SHA384RSA() {
            super(EvpMdRef.SHA384.EVP_MD);
        }
    }
    public static final class SHA512RSA extends RSAPKCS1Padding {
        public SHA512RSA() {
            super(EvpMdRef.SHA512.EVP_MD);
        }
    }

    public static final class SHA1ECDSA extends OpenSSLSignature {
        public SHA1ECDSA() {
            super(EvpMdRef.SHA1.EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA224ECDSA extends OpenSSLSignature {
        public SHA224ECDSA() {
            super(EvpMdRef.SHA224.EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA256ECDSA extends OpenSSLSignature {
        public SHA256ECDSA() {
            super(EvpMdRef.SHA256.EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA384ECDSA extends OpenSSLSignature {
        public SHA384ECDSA() {
            super(EvpMdRef.SHA384.EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA512ECDSA extends OpenSSLSignature {
        public SHA512ECDSA() {
            super(EvpMdRef.SHA512.EVP_MD, EngineType.EC);
        }
    }

    /**
     * Base class for {@code RSASSA-PSS} signatures.
     */
    abstract static class RSAPSSPadding extends OpenSSLSignature {
        private static final int TRAILER_FIELD_BC_ID = 1;

        private final String contentDigestAlgorithm;

        private String mgf1DigestAlgorithm;
        private long mgf1EvpMdRef;
        private int saltSizeBytes;

        RSAPSSPadding(
                long contentDigestEvpMdRef, String contentDigestAlgorithm, int saltSizeBytes) {
            super(contentDigestEvpMdRef, EngineType.RSA);
            this.contentDigestAlgorithm = contentDigestAlgorithm;
            this.mgf1DigestAlgorithm = contentDigestAlgorithm;
            this.mgf1EvpMdRef = contentDigestEvpMdRef;
            this.saltSizeBytes = saltSizeBytes;
        }

        @Override
        protected final void configureEVP_PKEY_CTX(long ctx)
                throws InvalidAlgorithmParameterException {
            NativeCrypto.EVP_PKEY_CTX_set_rsa_padding(ctx, NativeConstants.RSA_PKCS1_PSS_PADDING);
            NativeCrypto.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1EvpMdRef);
            NativeCrypto.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltSizeBytes);
        }

        @Override
        protected final void engineSetParameter(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            if (!(params instanceof PSSParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported parameter: " + params + ". Only "
                                + PSSParameterSpec.class.getName() + " supported");
            }
            PSSParameterSpec spec = (PSSParameterSpec) params;
            String specContentDigest = EvpMdRef
                    .getJcaDigestAlgorithmStandardName(spec.getDigestAlgorithm());
            if (specContentDigest == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported content digest algorithm: " + spec.getDigestAlgorithm());
            } else if (!contentDigestAlgorithm.equalsIgnoreCase(specContentDigest)) {
                throw new InvalidAlgorithmParameterException(
                        "Changing content digest algorithm not supported");
            }

            String specMgfAlgorithm = spec.getMGFAlgorithm();
            if (!EvpMdRef.MGF1_ALGORITHM_NAME.equalsIgnoreCase(specMgfAlgorithm)
                    && !EvpMdRef.MGF1_OID.equals(specMgfAlgorithm)) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported MGF algorithm: " + specMgfAlgorithm + ". Only "
                                + EvpMdRef.MGF1_ALGORITHM_NAME + " supported");
            }

            AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
            if (!(mgfSpec instanceof MGF1ParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported MGF parameters: " + mgfSpec + ". Only "
                                + MGF1ParameterSpec.class.getName() + " supported");
            }
            MGF1ParameterSpec specMgf1Spec = (MGF1ParameterSpec) spec.getMGFParameters();

            String specMgf1Digest = EvpMdRef
                    .getJcaDigestAlgorithmStandardName(specMgf1Spec.getDigestAlgorithm());
            if (specMgf1Digest == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported MGF1 digest algorithm: " + specMgf1Spec.getDigestAlgorithm());
            }
            long specMgf1EvpMdRef;
            try {
                specMgf1EvpMdRef = EvpMdRef
                        .getEVP_MDByJcaDigestAlgorithmStandardName(specMgf1Digest);
            } catch (NoSuchAlgorithmException e) {
                throw new ProviderException("Failed to obtain EVP_MD for " + specMgf1Digest, e);
            }

            int specSaltSizeBytes = spec.getSaltLength();
            if (specSaltSizeBytes < 0) {
                throw new InvalidAlgorithmParameterException(
                        "Salt length must be non-negative: " + specSaltSizeBytes);
            }

            int specTrailer = spec.getTrailerField();
            if (specTrailer != TRAILER_FIELD_BC_ID) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported trailer field: " + specTrailer + ". Only "
                                + TRAILER_FIELD_BC_ID + " supported");
            }

            this.mgf1DigestAlgorithm = specMgf1Digest;
            this.mgf1EvpMdRef = specMgf1EvpMdRef;
            this.saltSizeBytes = specSaltSizeBytes;

            long ctx = getEVP_PKEY_CTX();
            if (ctx != 0) {
                configureEVP_PKEY_CTX(ctx);
            }
        }

        @Override
        protected final AlgorithmParameters engineGetParameters() {
            try {
                AlgorithmParameters result = AlgorithmParameters.getInstance("PSS");
                result.init(
                        new PSSParameterSpec(
                                contentDigestAlgorithm,
                                EvpMdRef.MGF1_ALGORITHM_NAME,
                                new MGF1ParameterSpec(mgf1DigestAlgorithm),
                                saltSizeBytes,
                                TRAILER_FIELD_BC_ID));
                return result;
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                throw new ProviderException("Failed to create PSS AlgorithmParameters", e);
            }
        }
    }

    public static final class SHA1RSAPSS extends RSAPSSPadding {
        public SHA1RSAPSS() {
            super(EvpMdRef.SHA1.EVP_MD, EvpMdRef.SHA1.JCA_NAME, EvpMdRef.SHA1.SIZE_BYTES);
        }
    }

    public static final class SHA224RSAPSS extends RSAPSSPadding {
        public SHA224RSAPSS() {
            super(EvpMdRef.SHA224.EVP_MD, EvpMdRef.SHA224.JCA_NAME, EvpMdRef.SHA224.SIZE_BYTES);
        }
    }

    public static final class SHA256RSAPSS extends RSAPSSPadding {
        public SHA256RSAPSS() {
            super(EvpMdRef.SHA256.EVP_MD, EvpMdRef.SHA256.JCA_NAME, EvpMdRef.SHA256.SIZE_BYTES);
        }
    }

    public static final class SHA384RSAPSS extends RSAPSSPadding {
        public SHA384RSAPSS() {
            super(EvpMdRef.SHA384.EVP_MD, EvpMdRef.SHA384.JCA_NAME, EvpMdRef.SHA384.SIZE_BYTES);
        }
    }

    public static final class SHA512RSAPSS extends RSAPSSPadding {
        public SHA512RSAPSS() {
            super(EvpMdRef.SHA512.EVP_MD, EvpMdRef.SHA512.JCA_NAME, EvpMdRef.SHA512.SIZE_BYTES);
        }
    }
}
