/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Holds the KEM, KDF, and AEAD that are used and supported by {@link HpkeContextRecipient} and
 * {@link HpkeContextSender} defined on RFC 9180.
 *
 * <ul>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">KEM</a></li>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">KDF</a></li>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD</a></li>
 * </ul>
 */
public final class HpkeSuite {
    /**
     * KEM: 0x0020 DHKEM(X25519, HKDF-SHA256)
     */
    public static final int KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020;

    /**
     * KDF: 0x0001 HKDF-SHA256
     */
    public static final int KDF_HKDF_SHA256 = 0x0001;

    /**
     * AEAD: 0x0001 AES-128-GCM
     */
    public static final int AEAD_AES_128_GCM = 0x0001;

    /**
     * AEAD: 0x0002 AES-256-GCM
     */
    public static final int AEAD_AES_256_GCM = 0x0002;

    /**
     * AEAD: 0x0003 ChaCha20Poly1305
     */
    public static final int AEAD_CHACHA20POLY1305 = 0x0003;

    private final KEM mKem;
    private final KDF mKdf;
    private final AEAD mAead;

    public HpkeSuite(int kem, int kdf, int aead) {
        mKem = convertKem(kem);
        mKdf = convertKdf(kdf);
        mAead = convertAead(aead);
    }

    public HpkeSuite(KEM kem, KDF kdf, AEAD aead) {
        mKem = kem;
        mKdf = kdf;
        mAead = aead;
    }


    public String name() {
        return String.format("%s/%s/%s",
            mKem.name(), mKdf.name(), mAead.name());
    }

    /**
     * KEM configured while creating an instance of {@link HpkeSuite}
     *
     * @return kem
     */
    KEM getKem() {
        return mKem;
    }

    /**
     * KDF configured while creating an instance of {@link HpkeSuite}
     *
     * @return kdf
     */
    KDF getKdf() {
        return mKdf;
    }

    /**
     * AEAD configured while creating an instance of {@link HpkeSuite}
     *
     * @return aead
     */
    AEAD getAead() {
        return mAead;
    }

    /**
     * Converts the kem value into its {@link KEM} representation.
     *
     * @param kem value
     * @return {@link KEM} representation.
     */
    private KEM convertKem(int kem) {
        if (KEM_DHKEM_X25519_HKDF_SHA256 == kem) {
            return KEM.DHKEM_X25519_HKDF_SHA256;
        }
        throw new IllegalArgumentException("KEM " + kem + " not supported.");
    }

    /**
     * Converts the kdf value into its {@link KDF} representation.
     *
     * @param kdf value
     * @return {@link KDF} representation.
     */
    private KDF convertKdf(int kdf) {
        if (KDF_HKDF_SHA256 == kdf) {
            return KDF.HKDF_SHA256;
        }
        throw new IllegalArgumentException("KDF " + kdf + " not supported.");
    }

    /**
     * Converts the aead value into its {@link AEAD} representation.
     *
     * @param aead value
     * @return {@link AEAD} representation.
     */
    private AEAD convertAead(int aead) {
        switch (aead) {
            case AEAD_AES_128_GCM:
                return AEAD.AES_128_GCM;
            case AEAD_AES_256_GCM:
                return AEAD.AES_256_GCM;
            case AEAD_CHACHA20POLY1305:
                return AEAD.CHACHA20POLY1305;
            default:
                throw new IllegalArgumentException("AEAD " + aead + " not supported.");
        }
    }

    enum KEM {
        DHKEM_X25519_HKDF_SHA256(/* id= */ 0x0020, /* encLength= */ 32);

        private final int id;
        private final int encLength;

        KEM(int id, int encLength) {
            this.id = id;
            this.encLength = encLength;
        }

        /**
         * KEM id
         *
         * @return kem id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">KEM
         *         ids</a>
         */
        int getId() {
            return id;
        }

        /**
         * The length in bytes of an encapsulated key produced by this KEM.
         *
         * @return encapsulated key size in bytes
         */
        int getEncLength() {
            return encLength;
        }

        /**
         * Validates the encapsulated size in bytes matches the {@link KEM} spec.
         *
         * @param encapsulated encapsulated key produced by the kem
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">
         *     expected enc size</a>
         */
        void validateEncapsulatedLength(byte[] encapsulated) throws InvalidKeyException {
            Preconditions.checkNotNull(encapsulated, "encapsulated");
            final int expectedLength = this.getEncLength();
            if (encapsulated.length != expectedLength) {
                throw new InvalidKeyException(
                        "Expected encapsulated length of " + expectedLength + ", but was "
                                + encapsulated.length);
            }
        }

        /**
         * Validates the public key type and returns the raw bytes.
         *
         * @param publicKey alias pk
         * @return key in its raw format
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-algorithm-identifiers">expected
         *         pk size</a>
         */
        byte[] validatePublicKeyTypeAndGetRawKey(PublicKey publicKey) throws InvalidKeyException {
            String error;
            if (publicKey == null) {
                error = "null public key";
            } else if (!(publicKey instanceof OpenSSLX25519PublicKey)) {
                error = "Public key algorithm " + publicKey.getAlgorithm() + " is not supported";
            } else {
                return ((OpenSSLX25519PublicKey) publicKey).getU();
            }
            throw new InvalidKeyException(error);
        }

        /**
         * Validates the private key type and returns the raw bytes.
         *
         * @param privateKey alias sk
         * @return key in its raw format
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-algorithm-identifiers">expected
         *         sk size</a>
         */
        byte[] validatePrivateKeyTypeAndGetRawKey(PrivateKey privateKey)
                throws InvalidKeyException {
            String error;
            if (privateKey == null) {
                error = "null private key";
            } else if (!(privateKey instanceof OpenSSLX25519PrivateKey)) {
                error = "Private key algorithm " + privateKey.getAlgorithm() + " is not supported";
            } else {
                return ((OpenSSLX25519PrivateKey) privateKey).getU();
            }
            throw new InvalidKeyException(error);
        }
    }

    enum KDF {
        HKDF_SHA256(/* id= */ 0x0001, /* hLength= */ 32);

        private final int id;
        private final int hLength;

        KDF(int id, int hLength) {
            this.id = id;
            this.hLength = hLength;
        }

        /**
         * KDF id
         *
         * @return kdf id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">KDF
         *         ids</a>
         */
        int getId() {
            return id;
        }

        /**
         * The length in bytes for the output extract function.
         *
         * @return extract output size in bytes
         */
        int getHLength() {
            return hLength;
        }

        /**
         * Validates the secret export size in bytes. The size has a maximum value of 255*Nh bytes.
         *
         * @param l   expected exporter output length
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export">secret
         *         export</a>
         */
        void validateExportLength(int l) {
            long upperLimitLength = this.getHLength() * 255L;
            if (l < 0 || l > upperLimitLength) {
                throw new IllegalArgumentException("Export length (L) must be between 0 and "
                        + upperLimitLength + ", but was " + l);
            }
        }
    }

    enum AEAD {
        AES_128_GCM(/* id= */ 0x0001),
        AES_256_GCM(/* id= */ 0x0002),
        CHACHA20POLY1305(/* id= */ 0x0003);

        private final int id;

        AEAD(int id) {
            this.id = id;
        }

        /**
         * AEAD id in its decimal representation
         *
         * @return AEAD id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD
         *         ids</a>
         */
        int getId() {
            return id;
        }
    }
}
