/*
 * Copyright 2015 The Android Open Source Project
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

import static org.conscrypt.Preconditions.checkNotNull;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;

/**
 * HPKE parameter specifications used during a cipher operations to perform a
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-single-shot-apis">single shot API</a>.
 * The API to be used depends on the parameters defined while building the spec using the
 * {@link Builder} class.
 *
 * <p>Usage:
 * <pre>
 *     // Encryption with base mode
 *     final AlgorithmParameterSpec spec =
 *         new HpkeParameterSpec.Builder(id).modeBaseEncryption().build();
 *     cipher.init(Cipher.ENCRYPT_MODE, pk, spec);
 *
 *     // Decryption with base mode
 *     final AlgorithmParameterSpec spec =
 *         new HpkeParameterSpec.Builder(id).modeBaseDecryption(enc).build();
 *     cipher.init(Cipher.DECRYPT_MODE, sk, spec);
 *
 *     // Send export with base mode
 *     final AlgorithmParameterSpec spec =
 *         new HpkeParameterSpec.Builder(id).modeBaseSendExport(l).build();
 *     cipher.init(Cipher.ENCRYPT_MODE, pk, spec);
 *
 *     // Receive export with base mode
 *     final AlgorithmParameterSpec spec =
 *         new HpkeParameterSpec.Builder(id).modeBaseReceiveExport(enc, l).build();
 *     cipher.init(Cipher.DECRYPT_MODE, sk, spec);
 * </pre>
 */
public final class HpkeParameterSpec implements AlgorithmParameterSpec {
    /** Default parameter that can only be used for the Encryption API */
    public static final HpkeParameterSpec DEFAULT_ENCRYPTION = new HpkeParameterSpec.Builder(
        new HpkeAlgorithmIdentifier(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
            .modeBaseEncryption()
            .build();

    private final HpkeAlgorithmIdentifier algorithmIdentifier;
    private final byte[] enc;
    private final byte[] info;
    private final byte[] iv;
    private final byte[] psk;
    private final byte[] pskId;
    private final byte[] authKey;
    private final int l;

    private final boolean encrypting;
    private final boolean exporting;
    private final Mode mode;

    private HpkeParameterSpec(Builder builder) {
        this.algorithmIdentifier = builder.algorithmIdentifier;
        this.enc = builder.enc;
        this.info = builder.info;
        this.iv = builder.iv;
        this.psk = builder.psk;
        this.pskId = builder.pskId;
        this.authKey = builder.authKey;
        this.l = builder.l;
        this.encrypting = builder.encrypting;
        this.exporting = builder.exporting;
        this.mode = builder.mode;
    }

    /**
     * Returns the HPKE algorithm identifier.
     *
     * @return algorithm identifier specifying the KEM, KDF, and AEAD configured.
     */
    public HpkeAlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    /**
     * Returns the encapsulated key.
     *
     * @return enc creates a new array each time this method is called.
     */
    public byte[] getEnc() {
        return enc == null ? null : enc.clone();
    }

    /**
     * Returns the export length (L).
     *
     * @return L.
     */
    public int getL() {
        return l;
    }

    /**
     * Returns the caller's info.
     *
     * @return info creates a new array each time this method is called.
     */
    public byte[] getInfo() {
        return info == null ? null : info.clone();
    }

    /**
     * Returns the Initialization Vector (IV). The IV is a sender key value to be configured for
     * testing purposes only. Setting an IV avoids output randomness making it easier to validate
     * encryption results.
     *
     * @return IV creates a new array each time this method is called.
     */
    public byte[] getIv() {
        return iv == null ? null : iv.clone();
    }

    /**
     * Returns the pre-shared key (PSK) held by both the sender and recipient.
     *
     * @return psk creates a new array each time this method is called.
     */
    public byte[] getPsk() {
        return psk == null ? null : psk.clone();
    }

    /**
     * Returns an identifier for the PSK.
     *
     * @return psk identifier.
     */
    public byte[] getPskId() {
        return pskId == null ? null : pskId.clone();
    }

    /**
     * Returns key used for authentication using an asymmetric key, the key could be a private or
     * public key, depending on the mode. If encrypting or send export, then the key should be a
     * secret key. If decrypting or receive export, then the key should be a public key.
     *
     * @return public/private key for authentication using an asymmetric key.
     */
    public byte[] getAuthKey() {
        return authKey == null ? null : authKey.clone();
    }

    /**
     * Returns the HPKE mode configured. The possible modes are BASE, PSK, AUTH, and AUTH_PSK.
     *
     * @return mode
     */
    public Mode getMode() {
        return mode;
    }

    /**
     * Depending on how the {@link Builder} is initialized, returns a boolean telling if the API to
     * be used is either Secret Export or an Encryption/Decryption API. If true, then the API is
     * Secret Export.
     *
     * @return API configured, either Secret Export or Encryption/Decryption.
     */
    public boolean isExporting() {
        return exporting;
    }

    /**
     * Depending on how the {@link Builder} is initialized, returns a boolean telling if the
     * Cipher needs to be defined as {@link javax.crypto.Cipher#ENCRYPT_MODE} or
     * {@link javax.crypto.Cipher#DECRYPT_MODE}
     *
     * @return encryption mode
     */
    public boolean isEncrypting() {
        return encrypting;
    }

    public enum Mode {
        BASE, PSK, AUTH, AUTH_PSK
    }

    /**
     * Builder class to construct {@link HpkeParameterSpec}.
     * HPKE offers 2 APIs which are encryption/decryption and secret exports. It also offers 4 modes
     * which are base, psk, auth and auth_psk. This class provides a method to configure the API to
     * be used with its respective mode. Only one API and mode can be selected per instance.
     */
    public static class Builder {
        private static final byte[] DEFAULT_BYTES = new byte[0];
        private final HpkeAlgorithmIdentifier algorithmIdentifier;
        private byte[] enc;
        private byte[] info;
        private byte[] iv;
        private byte[] psk;
        private byte[] pskId;
        private byte[] authKey;
        private int l;

        private boolean encrypting;
        private boolean exporting;
        private Mode mode;
        private boolean modeSelected;

        /**
         * Constructor with the common parameters that all HPKE APIs and modes require
         *
         * @param algorithmIdentifier the algorithms kem, kdf, and aead identifiers
         */
        public Builder(HpkeAlgorithmIdentifier algorithmIdentifier) {
            this.algorithmIdentifier = checkNotNull(algorithmIdentifier, "algorithmIdentifier");
        }

        @Internal
        Builder(HpkeAlgorithmIdentifier algorithmIdentifier, byte[] enc, byte[] info, byte[] iv,
                int l, byte[] psk, byte[] pskId, byte[] authKey, Mode mode, boolean encrypting,
                boolean exporting) {
            this.modeSelected = true;
            this.algorithmIdentifier = algorithmIdentifier;
            this.enc = enc;
            this.info = info;
            this.iv = iv;
            this.l = l;
            this.psk = psk;
            this.pskId = pskId;
            this.authKey = authKey;
            this.mode = mode;
            this.encrypting = encrypting;
            this.exporting = exporting;
        }

        /**
         * Configures Encryption/Decryption API with base mode (0x00).
         *
         * @return builder
         */
        public Builder modeBaseEncryption() {
            checkInitializationOrInitialize();
            encrypting = true;
            exporting = false;
            mode = Mode.BASE;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with base mode (0x00)
         *
         * @param enc an encapsulated key produced by the algorithm
         * @return builder
         */
        public Builder modeBaseDecryption(byte[] enc) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            encrypting = false;
            exporting = false;
            mode = Mode.BASE;
            return this;
        }

        /**
         * Configures Secret Exports API with base mode (0x00)
         *
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeBaseSendExport(int l) {
            checkInitializationOrInitialize();
            checkAndCopyL(l);
            encrypting = true;
            exporting = true;
            mode = Mode.BASE;
            return this;
        }

        /**
         * Configures Secret Exports API with base mode (0x00)
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeBaseReceiveExport(byte[] enc, int l) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyL(l);
            encrypting = false;
            exporting = true;
            mode = Mode.BASE;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with psk mode (0x01).
         *
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @return builder
         */
        public Builder modePskEncryption(byte[] psk, byte[] pskId) {
            checkInitializationOrInitialize();
            checkAndCopyPsk(psk, pskId);
            encrypting = true;
            exporting = false;
            mode = Mode.PSK;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with psk mode (0x01).
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @return builder
         */
        public Builder modePskDecryption(byte[] enc, byte[] psk, byte[] pskId) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPsk(psk, pskId);
            encrypting = false;
            exporting = false;
            mode = Mode.PSK;
            return this;
        }

        /**
         * Configures Secret Exports API with psk mode (0x01)
         *
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modePskSendExport(byte[] psk, byte[] pskId, int l) {
            checkInitializationOrInitialize();
            checkAndCopyPsk(psk, pskId);
            checkAndCopyL(l);
            encrypting = true;
            exporting = true;
            mode = Mode.PSK;
            return this;
        }

        /**
         * Configures Secret Exports API with psk mode (0x01)
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modePskReceiveExport(byte[] enc, byte[] psk, byte[] pskId, int l) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPsk(psk, pskId);
            checkAndCopyL(l);
            encrypting = false;
            exporting = true;
            mode = Mode.PSK;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with auth mode (0x02).
         *
         * @param sk the sender private key for authentication
         * @return builder
         */
        public Builder modeAuthEncryption(byte[] sk) {
            checkInitializationOrInitialize();
            checkAndCopySecretKey(sk);
            encrypting = true;
            exporting = false;
            mode = Mode.AUTH;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with auth mode (0x02).
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param pk the sender public key for authentication
         * @return builder
         */
        public Builder modeAuthDecryption(byte[] enc, byte[] pk) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPublicKey(pk);
            encrypting = false;
            exporting = false;
            mode = Mode.AUTH;
            return this;
        }

        /**
         * Configures Secret Exports API with auth mode (0x02)
         *
         * @param sk the sender private key for authentication
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeAuthSendExport(byte[] sk, int l) {
            checkInitializationOrInitialize();
            checkAndCopySecretKey(sk);
            checkAndCopyL(l);
            encrypting = true;
            exporting = true;
            mode = Mode.AUTH;
            return this;
        }

        /**
         * Configures Secret Exports API with auth mode (0x02)
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param pk the sender public key for authentication
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeAuthReceiveExport(byte[] enc, byte[] pk, int l) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPublicKey(pk);
            checkAndCopyL(l);
            encrypting = false;
            exporting = true;
            mode = Mode.AUTH;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with auth psk mode (0x03).
         *
         * @param sk the sender private key for authentication
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @return builder
         */
        public Builder modeAuthPskEncryption(byte[] sk, byte[] psk, byte[] pskId) {
            checkInitializationOrInitialize();
            checkAndCopySecretKey(sk);
            checkAndCopyPsk(psk, pskId);
            encrypting = true;
            exporting = false;
            mode = Mode.AUTH_PSK;
            return this;
        }

        /**
         * Configures Encryption/Decryption API with auth psk mode (0x03).
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param pk the sender public key for authentication
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @return builder
         */
        public Builder modeAuthPskDecryption(byte[] enc, byte[] pk, byte[] psk, byte[] pskId) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPublicKey(pk);
            checkAndCopyPsk(psk, pskId);
            encrypting = false;
            exporting = false;
            mode = Mode.AUTH_PSK;
            return this;
        }

        /**
         * Configures Secret Exports API with auth psk mode (0x03)
         *
         * @param sk the sender private key for authentication
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeAuthPskSendExport(byte[] sk, byte[] psk, byte[] pskId, int l) {
            checkInitializationOrInitialize();
            checkAndCopySecretKey(sk);
            checkAndCopyPsk(psk, pskId);
            checkAndCopyL(l);
            encrypting = true;
            exporting = true;
            mode = Mode.AUTH_PSK;
            return this;
        }

        /**
         * Configures Secret Exports API with auth psk mode (0x03)
         *
         * @param enc an encapsulated key produced by the algorithm
         * @param pk the sender public key for authentication
         * @param psk a pre-shared key (PSK) held by both sender and recipient
         * @param pskId an identifier for the PSK
         * @param l the desired exported length (L) in bytes the desired exported length in bytes
         * @return builder
         */
        public Builder modeAuthPskReceiveExport(byte[] enc, byte[] pk, byte[] psk, byte[] pskId, int l) {
            checkInitializationOrInitialize();
            checkAndCopyEnc(enc);
            checkAndCopyPublicKey(pk);
            checkAndCopyPsk(psk, pskId);
            checkAndCopyL(l);
            encrypting = false;
            exporting = true;
            mode = Mode.AUTH_PSK;
            return this;
        }

        /**
         * The application-supplied information held by both sender and recipient
         *
         * @param info the application-supplied information
         * @return builder
         */
        public Builder info(byte[] info) {
            copyInfo(info);
            return this;
        }

        /**
         * This is to be used for testing algorithm correctness only. If setting this field,
         * encryption output won't have any randomness. Therefore, it is meant only for testing when
         * need to validate expected output results.
         *
         * @param iv is a sender private key meant for testing only
         * @return builder
         */
        public Builder iv(byte[] iv) {
            checkAndCopyIv(iv);
            return this;
        }

        /**
         * Checks if a mode has been selected and builds a new {@link HpkeParameterSpec}
         *
         * @return {@link HpkeParameterSpec}
         */
        public HpkeParameterSpec build() {
            if (!modeSelected) {
                throw new IllegalStateException("Please initialize builder with a valid mode");
            }
            return new HpkeParameterSpec(this);
        }

        private void checkAndCopyEnc(byte[] enc) {
            Preconditions.checkNotNull(enc, "enc");
            final int expectedLength = algorithmIdentifier.getKem().getEncLength();
            if (enc.length == expectedLength) {
                this.enc = Arrays.copyOf(enc, enc.length);
                return;
            }
            throw new IllegalArgumentException(
                "Expected enc length of " + expectedLength + " but was " + enc.length);
        }

        private void checkAndCopyIv(byte[] iv) {
            if (iv == null) {
                this.iv = null;
                return;
            }
            final int expectedLength = algorithmIdentifier.getKem().getSkLength();
            if (iv.length == expectedLength) {
                this.iv = Arrays.copyOf(iv, iv.length);
                return;
            }
            throw new IllegalArgumentException(
                "Expected IV length of " + expectedLength + " but was " + iv.length);

        }

        private void checkAndCopyL(int l) {
            long upperLimitLength = algorithmIdentifier.getKdf().getHLength() * 255L;
            if (l <= 0 || l > upperLimitLength) {
                throw new IllegalArgumentException(
                    "Export length (L) must be greater than 0 and less than " + upperLimitLength +
                        " but was " + l);
            }
            this.l = l;
        }

        private void checkAndCopyPsk(byte[] psk, byte[] pskId) {
            Preconditions.checkNotNull(psk, "psk");
            Preconditions.checkNotNull(pskId, "pskId");
            if (Arrays.equals(DEFAULT_BYTES, psk) ^ Arrays.equals(DEFAULT_BYTES, pskId)) {
                throw new IllegalArgumentException(
                    "Psk and psk id should not be empty values");
            }

            int minLength = algorithmIdentifier.getKdf().getHLength();
            if (psk.length < minLength) {
                throw new IllegalArgumentException(
                    "Psk length must be greater than or equal to " + minLength);
            }

            this.psk = Arrays.copyOf(psk, psk.length);
            this.pskId = Arrays.copyOf(pskId, pskId.length);
        }

        private void checkAndCopyPublicKey(byte[] pk) {
            Preconditions.checkNotNull(pk, "pk");
            final int expectedLength = algorithmIdentifier.getKem().getPkLength();
            if (pk.length != expectedLength) {
                throw new IllegalArgumentException(
                    "Expected pk length of " + expectedLength + " but was " + pk.length);
            }
            this.authKey = Arrays.copyOf(pk, pk.length);
        }

        private void checkAndCopySecretKey(byte[] sk) {
            Preconditions.checkNotNull(sk, "sk");
            final int expectedLength = algorithmIdentifier.getKem().getSkLength();
            if (sk.length != expectedLength) {
                throw new IllegalArgumentException(
                    "Expected sk length of " + expectedLength + " but was " + sk.length);
            }
            this.authKey = Arrays.copyOf(sk, sk.length);
        }

        private void copyInfo(byte[] info) {
            if (info == null) {
                this.info = null;
                return;
            }
            this.info = Arrays.copyOf(info, info.length);
        }

        private void checkInitializationOrInitialize() {
            if (modeSelected) {
                throw new IllegalStateException("Mode has already been configured");
            }
            modeSelected = true;
        }
    }
}
