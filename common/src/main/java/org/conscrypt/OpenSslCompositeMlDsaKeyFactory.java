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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/** An implementation of a {@link KeyFactorySpi} for composite MLDSA keys. */
@Internal
public abstract class OpenSslCompositeMlDsaKeyFactory extends KeyFactorySpi {
    private final CompositeMlDsaAlgorithm algorithm;

    private OpenSslCompositeMlDsaKeyFactory(CompositeMlDsaAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /** Key factory for MLDSA44-RSA2048-PSS-SHA256. */
    public static class Mldsa44Rsa2048PssSha256 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa44Rsa2048PssSha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    /** Key factory for MLDSA44-RSA2048-PKCS15-SHA256. */
    public static class Mldsa44Rsa2048Pkcs15Sha256 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa44Rsa2048Pkcs15Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    /** Key factory for MLDSA44-Ed25519-SHA512. */
    public static class Mldsa44Ed25519Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa44Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ED25519_SHA512);
        }
    }

    /** Key factory for MLDSA44-ECDSA-P256-SHA256. */
    public static class Mldsa44EcdsaP256Sha256 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa44EcdsaP256Sha256() {
            super(CompositeMlDsaAlgorithm.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    /** Key factory for MLDSA65-RSA3072-PSS-SHA512. */
    public static class Mldsa65Rsa3072PssSha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    /** Key factory for MLDSA65-RSA3072-PKCS15-SHA512. */
    public static class Mldsa65Rsa3072Pkcs15Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65Rsa3072Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    /** Key factory for MLDSA65-RSA4096-PSS-SHA512. */
    public static class Mldsa65Rsa4096PssSha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PSS_SHA512);
        }
    }

    /** Key factory for MLDSA65-RSA4096-PKCS15-SHA512. */
    public static class Mldsa65Rsa4096Pkcs15Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65Rsa4096Pkcs15Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_RSA4096_PKCS15_SHA512);
        }
    }

    /** Key factory for MLDSA65-ECDSA-P256-SHA512. */
    public static class Mldsa65EcdsaP256Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65EcdsaP256Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    /** Key factory for MLDSA65-ECDSA-P384-SHA512. */
    public static class Mldsa65EcdsaP384Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ECDSA_P384_SHA512);
        }
    }

    /** Key factory for MLDSA65-Ed25519-SHA512. */
    public static class Mldsa65Ed25519Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa65Ed25519Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA65_ED25519_SHA512);
        }
    }

    /** Key factory for MLDSA87-ECDSA-P384-SHA512. */
    public static class Mldsa87EcdsaP384Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa87EcdsaP384Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    /** Key factory for MLDSA87-RSA3072-PSS-SHA512. */
    public static class Mldsa87Rsa3072PssSha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa87Rsa3072PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA3072_PSS_SHA512);
        }
    }

    /** Key factory for MLDSA87-RSA4096-PSS-SHA512. */
    public static class Mldsa87Rsa4096PssSha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa87Rsa4096PssSha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_RSA4096_PSS_SHA512);
        }
    }

    /** Key factory for MLDSA87-ECDSA-P521-SHA512. */
    public static class Mldsa87EcdsaP521Sha512 extends OpenSslCompositeMlDsaKeyFactory {
        public Mldsa87EcdsaP521Sha512() {
            super(CompositeMlDsaAlgorithm.MLDSA87_ECDSA_P521_SHA512);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (!(keySpec instanceof EncodedKeySpec)) {
            throw new InvalidKeySpecException("Unsupported KeySpec");
        }
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec) keySpec;
        if (AddressUtils.asciiEqualsIgnoreCase(encodedKeySpec.getFormat(), "raw")) {
            return new OpenSslCompositeMlDsaPublicKey(encodedKeySpec.getEncoded(), algorithm);
        }
        if (!encodedKeySpec.getFormat().equals("X.509")) {
            throw new InvalidKeySpecException("Unsupported key format: "
                                              + encodedKeySpec.getFormat()
                                              + ". Only raw and X.509 keys are supported.");
        }
        byte[] rawKey = parseSubjectPublicKeyInfo(encodedKeySpec.getEncoded());
        return new OpenSslCompositeMlDsaPublicKey(rawKey, algorithm);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }
        if (!(keySpec instanceof EncodedKeySpec)) {
            throw new InvalidKeySpecException("Unsupported KeySpec");
        }
        EncodedKeySpec encodedKeySpec = (EncodedKeySpec) keySpec;
        if (encodedKeySpec.getFormat().equalsIgnoreCase("raw")) {
            return new OpenSslCompositeMlDsaPrivateKey(encodedKeySpec.getEncoded(), algorithm);
        }
        if (!encodedKeySpec.getFormat().equals("PKCS#8")) {
            throw new InvalidKeySpecException("Unsupported key format: "
                                              + encodedKeySpec.getFormat()
                                              + ". Only raw and PKCS#8 keys are supported.");
        }
        byte[] rawKey = parsePkcs8(encodedKeySpec.getEncoded());
        return new OpenSslCompositeMlDsaPrivateKey(rawKey, algorithm);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key null");
        }
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec null");
        }

        if (key instanceof OpenSslCompositeMlDsaPublicKey) {
            OpenSslCompositeMlDsaPublicKey conscryptKey = (OpenSslCompositeMlDsaPublicKey) key;
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                // Safe because keySpec is X509EncodedKeySpec or a superclass.
                T result = (T) new X509EncodedKeySpec(conscryptKey.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        } else if (key instanceof OpenSslCompositeMlDsaPrivateKey) {
            OpenSslCompositeMlDsaPrivateKey conscryptKey = (OpenSslCompositeMlDsaPrivateKey) key;
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                @SuppressWarnings("unchecked")
                // Safe because keySpec is PKCS8EncodedKeySpec or a superclass.
                T result = (T) new PKCS8EncodedKeySpec(key.getEncoded());
                return result;
            } else if (EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return KeySpecUtil.makeRawKeySpec(conscryptKey.getRaw(), keySpec);
            }
        }
        throw new InvalidKeySpecException("Unsupported keySpec: " + keySpec.getName());
    }

    @Override
    @SuppressWarnings("CanIgnoreReturnValueSuggester")
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof OpenSslCompositeMlDsaPublicKey
            || key instanceof OpenSslCompositeMlDsaPrivateKey) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key");
    }

    public CompositeMlDsaAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Format described in
     * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-encoding-to-der
     */
    private byte[] parsePkcs8(byte[] encoded) throws InvalidKeySpecException {
        byte[] rawKey = null;
        long pkcs8Parser = 0;
        long sequenceParser = 0;
        long oidParser = 0;

        try {
            pkcs8Parser = NativeCrypto.asn1_read_init(encoded);
            sequenceParser = NativeCrypto.asn1_read_sequence(pkcs8Parser);

            long version = NativeCrypto.asn1_read_uint64(sequenceParser);
            if (version != 0) {
                throw new InvalidKeySpecException("Invalid PKCS#8 version: " + version);
            }

            oidParser = NativeCrypto.asn1_read_sequence(sequenceParser);
            String oid = NativeCrypto.asn1_read_oid_raw(oidParser);
            String expectedOid = algorithm.getOid();
            if (!oid.equals(expectedOid)) {
                throw new InvalidKeySpecException("Incorrect Algorithm OID");
            }

            rawKey = NativeCrypto.asn1_read_octetstring(sequenceParser);
            if (rawKey == null || rawKey.length <= 32) {
                throw new InvalidKeySpecException("Invalid PKCS#8 encoding: key too short");
            }
            return rawKey;
        } catch (IOException e) {
            throw new InvalidKeySpecException("Failed to decode PKCS8 structure", e);
        } finally {
            NativeCrypto.asn1_read_free(pkcs8Parser);
            NativeCrypto.asn1_read_free(sequenceParser);
            NativeCrypto.asn1_read_free(oidParser);
        }
    }

    /**
     * Format described in
     * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-encoding-to-der
     */
    private byte[] parseSubjectPublicKeyInfo(byte[] encoded) throws InvalidKeySpecException {
        long spkiParser = 0;
        long sequenceParser = 0;
        long oidParser = 0;

        try {
            spkiParser = NativeCrypto.asn1_read_init(encoded);
            sequenceParser = NativeCrypto.asn1_read_sequence(spkiParser);

            oidParser = NativeCrypto.asn1_read_sequence(sequenceParser);
            String oid = NativeCrypto.asn1_read_oid_raw(oidParser);
            String expectedOid = algorithm.getOid();
            if (!oid.equals(expectedOid)) {
                throw new InvalidKeySpecException("Incorrect Algorithm OID");
            }

            // Read the raw key payload and ensure that the padding bits are exactly 0.
            byte[] rawKey = NativeCrypto.asn1_read_bitstring_payload(sequenceParser, 0);
            if (rawKey == null || rawKey.length <= 1312) { // ML-DSA-44 public key size
                throw new InvalidKeySpecException("Invalid X.509 SPKI encoding: key too short");
            }
            return rawKey;
        } catch (IOException e) {
            throw new InvalidKeySpecException("Failed to decode X.509 structure", e);
        } finally {
            NativeCrypto.asn1_read_free(spkiParser);
            NativeCrypto.asn1_read_free(sequenceParser);
            NativeCrypto.asn1_read_free(oidParser);
        }
    }
}
