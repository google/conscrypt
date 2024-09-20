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
        mKem = KEM.forId(kem);
        mKdf = KDF.forId(kdf);
        mAead = AEAD.forId(aead);
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
    public KEM getKem() {
        return mKem;
    }

    /**
     * KDF configured while creating an instance of {@link HpkeSuite}
     *
     * @return kdf
     */
    public KDF getKdf() {
        return mKdf;
    }

    /**
     * AEAD configured while creating an instance of {@link HpkeSuite}
     *
     * @return aead
     */
    public AEAD getAead() {
        return mAead;
    }

    /**
     * Converts the KEM value into its {@link KEM} representation.
     *
     * @param kem value
     * @return {@link KEM} representation.
     */
    @Deprecated // Use KEM.forId()
    public KEM convertKem(int kem) {
        return KEM.forId(kem);
    }

    /**
     * Converts the KDF value into its {@link KDF} representation.
     *
     * @param kdf value
     * @return {@link KDF} representation.
     */
    @Deprecated // Use KDF.forId()
    public KDF convertKdf(int kdf) {
        return KDF.forId(kdf);
    }

    /**
     * Converts the AEAD value into its {@link AEAD} representation.
     *
     * @param aead value
     * @return {@link AEAD} representation.
     */
    @Deprecated // Use AEAD.forId()
    public AEAD convertAead(int aead) {
        return AEAD.forId(aead);
    }

    /**
     * Key Encapsulation Mechanisms (KEMs)
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">
     *         rfc9180 </a>
     */
    public enum KEM {
        DHKEM_X25519_HKDF_SHA256(
                /* id= */ 0x20, /* nSecret= */ 32, /* nEnc= */ 32, /* nPk= */ 32, /* nSk= */ 32);

        private final int id;
        private final int nSecret;
        private final int nEnc;
        private final int nPk;
        private final int nSk;

        KEM(int id, int nSecret, int nEnc, int nPk, int nSk) {
            this.id = id;
            this.nSecret = nSecret;
            this.nEnc = nEnc;
            this.nPk = nPk;
            this.nSk = nSk;
        }

        /**
         * KEM id
         *
         * @return kem id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">KEM
         *         ids</a>
         */
        public int getId() {
            return id;
        }

        /**
         * Returns the  length in bytes of an encapsulated key produced by this KEM.
         */
        @Deprecated // Use getEncapsulatedLength
        public int getnEnc() {
            return getEncapsulatedLength();
        }
        public int getEncapsulatedLength() {
            return nEnc;
        }

        /**
         * Returns the length in bytes of a KEM shared secret produced by this KEM.
         */
        public int getSecretLength() {
            return nSecret;
        }

        /**
         * Returns the length in bytes of an encoded public key for this KEM.
         */
        public int getPublicKeyLength() {
            return nPk;
        }

        /**
         * Returns The length in bytes of an encoded private key for this KEM.
         */
        public int getPrivateKeyLength() {
            return nSk;
        }

        /**
         * Returns the KEM value for a given id.
         */
        public static KEM forId(int id) {
            for (KEM kem : values()) {
                if (kem.getId() == id) {
                    return kem;
                }
            }
            throw new IllegalArgumentException("Unknown KEM " + id);
        }
    }

    /**
     * Key Derivation Functions (KDFs)
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">
     *         rfc9180</a>
     */
    public enum KDF {
        HKDF_SHA256(/* id= */ 0x0001, /* hLength= */ 32, /* hName= */ "HmacSHA256");

        private final int id;
        private final int hLength;
        private final String hName;

        KDF(int id, int hLength, String hName) {
            this.id = id;
            this.hLength = hLength;
            this.hName = hName;
        }

        /**
         * KDF id
         *
         * @return kdf id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">KDF
         *         ids</a>
         */
        public int getId() {
            return id;
        }

        /**
         * The length in bytes for the output extract function.
         *
         * @return extract output size in bytes
         */
        public int getMacLength() {
            return hLength;
        }
        @Deprecated // Use getMacLength
        public int getHLength() {
            return getMacLength();
        }

        /**
         * Returns the maximum export length that can be supported with this KDF.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export">secret
         *         export</a>
         */
        public long maxExportLength() {
            return this.getMacLength() * 255L;
        }

        /**
         * Name as defined in {@link javax.crypto.Mac}.
         *
         * @return name of mac algorithm used by the kdf.
         */
        @Deprecated // Use getMacName
        public String getMacAlgorithmName() {
            return getMacName();
        }
        public String getMacName() {
            return hName;
        }

        /**
         * Returns the KDF value for a given id.
         */
        public static KDF forId(int id) {
            for (KDF kdf : values()) {
                if (kdf.getId() == id) {
                    return kdf;
                }
            }
            throw new IllegalArgumentException("Unknown KDF " + id);
        }
    }

    /**
     * AEAD ciphers.
     *
     * @see <a
     *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD
     *         ids</a>
     */
    public enum AEAD {
        AES_128_GCM(/* id= */ AEAD_AES_128_GCM, /* nk= */ 16, /* nn= */ 12, /* nt= */ 16),
        AES_256_GCM(/* id= */ AEAD_AES_256_GCM, /* nk= */ 32, /* nn= */ 12, /* nt= */ 16),
        CHACHA20POLY1305(/* id= */ AEAD_CHACHA20POLY1305, /* nk= */ 32, /* nn= */ 12, /* nt= */ 16);

        private final int id;
        private final int nk;
        private final int nn;
        private final int nt;

        AEAD(int id, int nk, int nn, int nt) {
            this.id = id;
            this.nk = nk;
            this.nn = nn;
            this.nt = nt;
        }

        /**
         * AEAD id in its decimal representation
         *
         * @return AEAD id
         * @see <a
         *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD
         *         ids</a>
         */
        public int getId() {
            return id;
        }
        /**
         * Returns the length in bytes of a key for this algorithm.
         *
         * @return AEAD Nk
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">
         *         AEAD ids</a>
         */
        @Deprecated // Use getKeyLength()
        public int getNk() {
            return getKeyLength();
        }
        public int getKeyLength() {
            return nk;
        }

        /**
         * Returns the length in bytes of a nonce for this algorithm.
         *
         * @return AEAD Nn
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">
         *         AEAD ids</a>
         */
        @Deprecated // Use getNonceLength()
        public int getNn() {
            return getNonceLength();
        }
        public int getNonceLength() {
            return nn;
        }

        /**
         * Returns the length in bytes of the AEAD authentication tag for this algorithm.
         *
         * @return AEAD Nt
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">
         *         AEAD ids</a>
         */
        @Deprecated // Use getTagLength()
        public int getNt() {
            return nt;
        }
        public int getTagLength() {
            return nt;
        }

        /**
         * Returns the AEAD value for a given id.
         */
        public static AEAD forId(int id) {
            for (AEAD aead : values()) {
                if (aead.getId() == id) {
                    return aead;
                }
            }
            throw new IllegalArgumentException("Unknown AEAD " + id);
        }
    }
}
