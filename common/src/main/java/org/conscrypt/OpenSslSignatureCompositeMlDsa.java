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

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;

/** An implementation of a {@link SignatureSpi} for Composite ML-DSA keys. */
@Internal
public abstract class OpenSslSignatureCompositeMlDsa extends SignatureSpi {
    private final CompositeMlDsaAlgorithm algorithm;
    private OpenSSLMessageDigestJDK messageDigest;
    private OpenSslCompositeMlDsaPrivateKey signKey;
    private OpenSslCompositeMlDsaPublicKey verifyKey;

    private OpenSslSignatureCompositeMlDsa(CompositeMlDsaAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /** Signature for MLDSA44-RSA2048-PSS-SHA256. */
    public static class Mldsa44Rsa2048PssSha256 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa44Rsa2048PssSha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    /** Signature for MLDSA44-RSA2048-PKCS15-SHA256. */
    public static class Mldsa44Rsa2048Pkcs15Sha256 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa44Rsa2048Pkcs15Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    /** Signature for MLDSA44-Ed25519-SHA512. */
    public static class Mldsa44Ed25519Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa44Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512);
        }
    }

    /** Signature for MLDSA44-ECDSA-P256-SHA256. */
    public static class Mldsa44EcdsaP256Sha256 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa44EcdsaP256Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    /** Signature for MLDSA65-RSA3072-PSS-SHA512. */
    public static class Mldsa65Rsa3072PssSha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    /** Signature for MLDSA65-RSA3072-PKCS15-SHA512. */
    public static class Mldsa65Rsa3072Pkcs15Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65Rsa3072Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    /** Signature for MLDSA65-RSA4096-PSS-SHA512. */
    public static class Mldsa65Rsa4096PssSha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PSS_SHA512);
        }
    }

    /** Signature for MLDSA65-RSA4096-PKCS15-SHA512. */
    public static class Mldsa65Rsa4096Pkcs15Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65Rsa4096Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PKCS15_SHA512);
        }
    }

    /** Signature for MLDSA65-Ed25519-SHA512. */
    public static class Mldsa65Ed25519Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ED25519_SHA512);
        }
    }

    /** Signature for MLDSA65-ECDSA-P256-SHA512. */
    public static class Mldsa65EcdsaP256Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65EcdsaP256Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    /** Signature for MLDSA65-ECDSA-P384-SHA512. */
    public static class Mldsa65EcdsaP384Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa65EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P384_SHA512);
        }
    }

    /** Signature for MLDSA87-RSA3072-PSS-SHA512. */
    public static class Mldsa87Rsa3072PssSha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa87Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA3072_PSS_SHA512);
        }
    }

    /** Signature for MLDSA87-RSA4096-PSS-SHA512. */
    public static class Mldsa87Rsa4096PssSha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa87Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA4096_PSS_SHA512);
        }
    }

    /** Signature for MLDSA87-ECDSA-P384-SHA512. */
    public static class Mldsa87EcdsaP384Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa87EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    /** Signature for MLDSA87-ECDSA-P521-SHA512. */
    public static class Mldsa87EcdsaP521Sha512 extends OpenSslSignatureCompositeMlDsa {
        public Mldsa87EcdsaP521Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P521_SHA512);
        }
    }

    private void resetDigest() {
        try {
            switch (algorithm.getPreHashAlgorithm()) {
                case "SHA-512":
                    messageDigest = new OpenSSLMessageDigestJDK.SHA512();
                    break;
                case "SHA-256":
                    messageDigest = new OpenSSLMessageDigestJDK.SHA256();
                    break;
                default:
                    throw new IllegalStateException("Unsupported pre-hash algorithm: "
                                                    + algorithm.getPreHashAlgorithm());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to create message digest", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (messageDigest == null) {
            throw new SignatureException("Not initialized");
        }
        messageDigest.engineUpdate(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (messageDigest == null) {
            throw new SignatureException("Not initialized");
        }
        messageDigest.engineUpdate(b, off, len);
    }

    @Override
    @SuppressWarnings("deprecation") // SignatureSpi requires implementing this deprecated method.
    protected Object engineGetParameter(String param) {
        return null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof OpenSslCompositeMlDsaPrivateKey)) {
            throw new InvalidKeyException("Require OpenSslCompositeMlDsaPrivateKey");
        }
        if (((OpenSslCompositeMlDsaPrivateKey) privateKey).getCompositeMlDsaAlgorithm()
            != algorithm) {
            throw new InvalidKeyException(
                    "Algorithm mismatch: expected " + algorithm + ", got "
                    + ((OpenSslCompositeMlDsaPrivateKey) privateKey).getCompositeMlDsaAlgorithm());
        }
        this.signKey = (OpenSslCompositeMlDsaPrivateKey) privateKey;
        this.verifyKey = null;
        resetDigest();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof OpenSslCompositeMlDsaPublicKey)) {
            throw new InvalidKeyException("Require OpenSslCompositeMlDsaPublicKey");
        }
        if (((OpenSslCompositeMlDsaPublicKey) publicKey).getCompositeMlDsaAlgorithm()
            != algorithm) {
            throw new InvalidKeyException(
                    "Algorithm mismatch: expected " + algorithm + ", got "
                    + ((OpenSslCompositeMlDsaPublicKey) publicKey).getCompositeMlDsaAlgorithm());
        }
        this.verifyKey = (OpenSslCompositeMlDsaPublicKey) publicKey;
        this.signKey = null;
        resetDigest();
    }

    @Override
    @SuppressWarnings("deprecation") // SignatureSpi requires implementing this deprecated method.
    protected void engineSetParameter(String param, Object value) {}

    // https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-pre-hashing
    private byte[] createMessageRepresentative() throws SignatureException {
        byte[] prefix = "CompositeAlgorithmSignatures2025".getBytes(US_ASCII);
        byte[] label = algorithm.getLabel().getBytes(US_ASCII);

        if (messageDigest == null) {
            throw new SignatureException("Not initialized");
        }

        byte[] messageHash = messageDigest.engineDigest();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(prefix);
            outputStream.write(label);
            outputStream.write((byte) 0); // len(ctx)
            outputStream.write(messageHash);
        } catch (IOException e) {
            throw new SignatureException("Failed to create message representative", e);
        }

        return outputStream.toByteArray();
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signKey == null) {
            // Should never happen.
            throw new SignatureException("No key provided");
        }

        // Calculate message representative.
        byte[] messageRepresentative = createMessageRepresentative();

        // Calculate ML-DSA signature with `ctx`.
        // (`ctx` here means the signature context in Algorithm 2 in
        // https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        long evpPkeyCtx = NativeCrypto.EVP_DigestSignInit(
                ctxLocal, 0, signKey.getMlDsaPrivateKey().getOpenSSLKey().getNativeRef());
        byte[] mldsaCtx = algorithm.getLabel().getBytes(US_ASCII);
        NativeCrypto.EVP_PKEY_CTX_set1_signature_context_string(evpPkeyCtx, mldsaCtx);
        byte[] mldsaSig = NativeCrypto.EVP_DigestSign(ctxLocal, messageRepresentative, 0,
                                                      messageRepresentative.length);

        // Calculate traditional signature.
        byte[] tradSig;
        switch (algorithm.getClassicAlgorithm()) {
            case "Ed25519":
                OpenSslSignatureEdDsa edDsaSigner = new OpenSslSignatureEdDsa();
                try {
                    edDsaSigner.engineInitSign(signKey.getClassicPrivateKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize Ed25519 signature", e);
                }
                edDsaSigner.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradSig = edDsaSigner.engineSign();
                break;
            case "RSA":
                OpenSSLSignature rsaSigner;
                String classicSignatureDigest = algorithm.getClassicSignatureDigest();
                if (classicSignatureDigest == null) {
                    throw new IllegalStateException("Classic signature digest is null");
                }
                if (algorithm.isPss()) {
                    if (classicSignatureDigest.equals("SHA-256")) {
                        rsaSigner = new OpenSSLSignature.SHA256RSAPSS();
                    } else if (classicSignatureDigest.equals("SHA-384")) {
                        rsaSigner = new OpenSSLSignature.SHA384RSAPSS();
                    } else if (classicSignatureDigest.equals("SHA-512")) {
                        rsaSigner = new OpenSSLSignature.SHA512RSAPSS();
                    } else {
                        throw new IllegalStateException("Unsupported digest: "
                                                        + classicSignatureDigest);
                    }
                } else {
                    // PKCS#1 v1.5
                    if (classicSignatureDigest.equals("SHA-256")) {
                        rsaSigner = new OpenSSLSignature.SHA256RSA();
                    } else if (classicSignatureDigest.equals("SHA-384")) {
                        rsaSigner = new OpenSSLSignature.SHA384RSA();
                    } else if (classicSignatureDigest.equals("SHA-512")) {
                        rsaSigner = new OpenSSLSignature.SHA512RSA();
                    } else {
                        throw new IllegalStateException("Unsupported digest: "
                                                        + classicSignatureDigest);
                    }
                }
                try {
                    rsaSigner.engineInitSign(signKey.getClassicPrivateKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize RSA signature", e);
                }
                rsaSigner.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradSig = rsaSigner.engineSign();
                break;
            case "EC":
                OpenSSLSignature ecDsaSigner;
                classicSignatureDigest = algorithm.getClassicSignatureDigest();
                if (classicSignatureDigest == null) {
                    throw new IllegalStateException("Classic signature digest is null");
                }
                if (classicSignatureDigest.equals("SHA-256")) {
                    ecDsaSigner = new OpenSSLSignature.SHA256ECDSA();
                } else if (classicSignatureDigest.equals("SHA-384")) {
                    ecDsaSigner = new OpenSSLSignature.SHA384ECDSA();
                } else if (classicSignatureDigest.equals("SHA-512")) {
                    ecDsaSigner = new OpenSSLSignature.SHA512ECDSA();
                } else {
                    throw new IllegalStateException("Unsupported digest: "
                                                    + classicSignatureDigest);
                }
                try {
                    ecDsaSigner.engineInitSign(signKey.getClassicPrivateKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize EC signature", e);
                }
                ecDsaSigner.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradSig = ecDsaSigner.engineSign();
                break;
            default:
                throw new IllegalStateException("Unsupported classic algorithm: "
                                                + algorithm.getClassicAlgorithm());
        }

        byte[] sig = new byte[mldsaSig.length + tradSig.length];
        System.arraycopy(mldsaSig, 0, sig, 0, mldsaSig.length);
        System.arraycopy(tradSig, 0, sig, mldsaSig.length, tradSig.length);

        return sig;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey == null) {
            // Should never happen.
            throw new SignatureException("No verify key provided");
        }

        byte[] messageRepresentative = createMessageRepresentative();

        int mldsaSigLength;
        if (algorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_44)) {
            mldsaSigLength = 2420;
        } else if (algorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_65)) {
            mldsaSigLength = 3309;
        } else if (algorithm.getMlDsaAlgorithm().equals(MlDsaAlgorithm.ML_DSA_87)) {
            mldsaSigLength = 4627;
        } else {
            throw new IllegalStateException("Unsupported ML-DSA algorithm: "
                                            + algorithm.getMlDsaAlgorithm());
        }

        if (sigBytes.length <= mldsaSigLength) {
            return false;
        }

        byte[] mldsaSig = Arrays.copyOfRange(sigBytes, 0, mldsaSigLength);
        byte[] tradSig = Arrays.copyOfRange(sigBytes, mldsaSigLength, sigBytes.length);

        // Verify ML-DSA signature with `ctx`.
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        long evpPkeyCtx = NativeCrypto.EVP_DigestVerifyInit(
                ctxLocal, 0, verifyKey.getMlDsaPublicKey().getOpenSSLKey().getNativeRef());
        byte[] mldsaCtx = algorithm.getLabel().getBytes(US_ASCII);
        NativeCrypto.EVP_PKEY_CTX_set1_signature_context_string(evpPkeyCtx, mldsaCtx);
        boolean mldsaVerified = NativeCrypto.EVP_DigestVerify(
                ctxLocal, mldsaSig, 0, mldsaSig.length, messageRepresentative, 0,
                messageRepresentative.length);

        boolean tradVerified = false;
        switch (algorithm.getClassicAlgorithm()) {
            case "Ed25519":
                OpenSslSignatureEdDsa edDsaVerifier = new OpenSslSignatureEdDsa();
                try {
                    edDsaVerifier.engineInitVerify(verifyKey.getClassicPublicKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize Ed25519 signature", e);
                }
                edDsaVerifier.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradVerified = edDsaVerifier.engineVerify(tradSig);
                break;
            case "RSA":
                OpenSSLSignature rsaVerifier;
                String classicSignatureDigest = algorithm.getClassicSignatureDigest();
                if (classicSignatureDigest == null) {
                    throw new IllegalStateException("Classic signature digest is null");
                }
                if (algorithm.isPss()) {
                    if (classicSignatureDigest.equals("SHA-256")) {
                        rsaVerifier = new OpenSSLSignature.SHA256RSAPSS();
                    } else if (classicSignatureDigest.equals("SHA-384")) {
                        rsaVerifier = new OpenSSLSignature.SHA384RSAPSS();
                    } else if (classicSignatureDigest.equals("SHA-512")) {
                        rsaVerifier = new OpenSSLSignature.SHA512RSAPSS();
                    } else {
                        throw new IllegalStateException("Unsupported digest: "
                                                        + classicSignatureDigest);
                    }
                } else {
                    // PKCS#1 v1.5
                    if (classicSignatureDigest.equals("SHA-256")) {
                        rsaVerifier = new OpenSSLSignature.SHA256RSA();
                    } else if (classicSignatureDigest.equals("SHA-384")) {
                        rsaVerifier = new OpenSSLSignature.SHA384RSA();
                    } else if (classicSignatureDigest.equals("SHA-512")) {
                        rsaVerifier = new OpenSSLSignature.SHA512RSA();
                    } else {
                        throw new IllegalStateException("Unsupported digest: "
                                                        + classicSignatureDigest);
                    }
                }
                try {
                    rsaVerifier.engineInitVerify(verifyKey.getClassicPublicKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize RSA signature", e);
                }
                rsaVerifier.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradVerified = rsaVerifier.engineVerify(tradSig);
                break;
            case "EC":
                OpenSSLSignature ecDsaVerifier;
                classicSignatureDigest = algorithm.getClassicSignatureDigest();
                if (classicSignatureDigest == null) {
                    throw new IllegalStateException("Classic signature digest is null");
                }
                if (classicSignatureDigest.equals("SHA-256")) {
                    ecDsaVerifier = new OpenSSLSignature.SHA256ECDSA();
                } else if (classicSignatureDigest.equals("SHA-384")) {
                    ecDsaVerifier = new OpenSSLSignature.SHA384ECDSA();
                } else if (classicSignatureDigest.equals("SHA-512")) {
                    ecDsaVerifier = new OpenSSLSignature.SHA512ECDSA();
                } else {
                    throw new IllegalStateException("Unsupported digest: "
                                                    + classicSignatureDigest);
                }
                try {
                    ecDsaVerifier.engineInitVerify(verifyKey.getClassicPublicKey());
                } catch (InvalidKeyException e) {
                    throw new SignatureException("Failed to initialize EC signature", e);
                }
                ecDsaVerifier.engineUpdate(messageRepresentative, 0, messageRepresentative.length);
                tradVerified = ecDsaVerifier.engineVerify(tradSig);
                break;
            default:
                throw new IllegalStateException("Unsupported classic algorithm: "
                                                + algorithm.getClassicAlgorithm());
        }
        return (mldsaVerified && tradVerified);
    }
}
