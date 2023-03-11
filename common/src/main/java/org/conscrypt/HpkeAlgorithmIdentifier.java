package org.conscrypt;

import static org.conscrypt.Preconditions.checkNotNull;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

/**
 * KEM, KDF, and AEAD algorithm identifiers and specs defined on RFC 9180.
 * <ul>
 *   <li><a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">KEM</a></li>
 *   <li><a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">KDF</a></li>
 *   <li><a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD</a></li>
 * </ul>
 */
public class HpkeAlgorithmIdentifier {

    public enum KEM {
        DHKEM_P_256_HKDF_SHA256, DHKEM_P_384_HKDF_SHA384, DHKEM_P_521_HKDF_SHA512, DHKEM_X25519_HKDF_SHA256, DHKEM_X448_HKDF_SHA512;

        private static final Map<KEM, Spec> SPEC_LENGTH_IN_BYTES = new HashMap<>();
        static {
            SPEC_LENGTH_IN_BYTES.put(
                DHKEM_P_256_HKDF_SHA256,
                new Spec(/* secret= */ 32,/* enc= */ 65,/* pk= */ 65,/* sk= */ 32));
            SPEC_LENGTH_IN_BYTES.put(
                DHKEM_P_384_HKDF_SHA384,
                new Spec(/* secret= */ 48,/* enc= */ 97,/* pk= */ 97,/* sk= */ 48));
            SPEC_LENGTH_IN_BYTES.put(
                DHKEM_P_521_HKDF_SHA512,
                new Spec(/* secret= */ 64,/* enc= */ 133,/* pk= */ 133,/* sk= */ 66));
            SPEC_LENGTH_IN_BYTES.put(
                DHKEM_X25519_HKDF_SHA256,
                new Spec(/* secret= */ 32,/* enc= */ 32,/* pk= */ 32,/* sk= */ 32));
            SPEC_LENGTH_IN_BYTES.put(
                DHKEM_X448_HKDF_SHA512,
                new Spec(/* secret= */ 64,/* enc= */ 56,/* pk= */ 56,/* sk= */ 56));
        }

        /**
         * The length in bytes of a KEM shared secret produced by this KEM.
         *
         * @return shared secret size in bytes
         */
        public int getSecretLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).secret;
        }

        /**
         * The length in bytes of an encapsulated key produced by this KEM.
         *
         * @return encapsulated key size in bytes
         */
        public int getEncLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).enc;
        }

        /**
         * The length in bytes of an encoded public key for this KEM.
         *
         * @return public key size in bytes
         */
        public int getPkLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).pk;
        }

        /**
         * The length in bytes of an encoded private key for this KEM.
         *
         * @return private key size in bytes
         */
        public int getSkLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).sk;
        }

        /**
         * Splits the value that {@link Cipher#doFinal()} returns. The value returned is an
         * encapsulated key and ciphertext concatenated. This helps splits them apart.
         *
         * @param encapsulatedKeyAndCiphertext the concatenated value of enc + ciphertext
         * @return sealedData
         */
        public SealedData extract(byte[] encapsulatedKeyAndCiphertext) {
            Preconditions.checkNotNull(encapsulatedKeyAndCiphertext, "encapsulatedKeyAndCiphertext");
            final int expectedEncLength = this.getEncLength();
            if (encapsulatedKeyAndCiphertext.length < expectedEncLength) {
                throw new IllegalArgumentException("Invalid encapsulated key length");
            } else if (encapsulatedKeyAndCiphertext.length == expectedEncLength) {
                throw new IllegalArgumentException("Invalid ciphertext length");
            }

            byte[] enc = new byte[expectedEncLength];
            byte[] ct = new byte[encapsulatedKeyAndCiphertext.length - enc.length];
            System.arraycopy(encapsulatedKeyAndCiphertext, 0, enc, 0, enc.length);
            System.arraycopy(encapsulatedKeyAndCiphertext, enc.length, ct, 0, ct.length);
            return new SealedData(enc, ct);
        }

        /**
         * Representation of the encapsulated key and the ciphertext in their respective fields
         */
        public static class SealedData {
            private final byte[] enc;
            private final byte[] ct;

            private SealedData(byte[] enc, byte[] ct) {
                this.enc = enc;
                this.ct = ct;
            }

            /**
             * The encapsulated key (enc)
             *
             * @return enc
             */
            public byte[] getEnc() {
                return enc;
            }

            /**
             * The ciphertext or the exported value depending on the HPKE API mode
             *
             * @return ciphertext/exported
             */
            public byte[] getCt() {
                return ct;
            }
        }

        private static class Spec {
            private final int secret;
            private final int enc;
            private final int pk;
            private final int sk;

            private Spec(int secret, int enc, int pk, int sk) {
                this.secret = secret;
                this.enc = enc;
                this.pk = pk;
                this.sk = sk;
            }
        }
    }

    public enum KDF {
        HKDF_SHA256, HKDF_SHA384, HKDF_SHA512;

        private static final Map<KDF, Integer> H_LENGTH_IN_BYTES = new HashMap<>();
        static {
            H_LENGTH_IN_BYTES.put(HKDF_SHA256, 32);
            H_LENGTH_IN_BYTES.put(HKDF_SHA384, 48);
            H_LENGTH_IN_BYTES.put(HKDF_SHA512, 64);
        }

        /**
         * The length in bytes for the output extract function.
         *
         * @return extract output size in bytes
         */
        public int getHLength() {
            return H_LENGTH_IN_BYTES.get(this);
        }
    }

    public enum AEAD {
        AES_128_GCM, AES_256_GCM, CHACHA20POLY1305, EXPORT_ONLY_AEAD;

        private static final Map<AEAD, Spec> SPEC_LENGTH_IN_BYTES = new HashMap<>();
        static {
            SPEC_LENGTH_IN_BYTES.put(
                AES_128_GCM,
                new Spec(/* k= */ 16,/* n= */ 12,/* t= */ 16));
            SPEC_LENGTH_IN_BYTES.put(
                AES_256_GCM,
                new Spec(/* k= */ 32,/* n= */ 12,/* t= */ 16));
            SPEC_LENGTH_IN_BYTES.put(
                CHACHA20POLY1305,
                new Spec(/* k= */ 32,/* n= */ 12,/* t= */ 16));
            SPEC_LENGTH_IN_BYTES.put(
                EXPORT_ONLY_AEAD,
                new Spec(/* k= */ -1,/* n= */ -1,/* t= */ -1));
        }

        /**
         * The length in bytes of a key for this algorithm.
         *
         * @return key size in bytes
         */
        public int getKLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).k;
        }

        /**
         * The length in bytes of a nonce for this algorithm.
         *
         * @return nonce size in bytes
         */
        public int getNLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).n;
        }

        /**
         * The length in bytes of the authentication tag for this algorithm.
         *
         * @return authentication tag size in bytes
         */
        public int getTLength() {
            return SPEC_LENGTH_IN_BYTES.get(this).t;
        }

        private static class Spec {
            private final int k;
            private final int n;
            private final int t;

            private Spec(int k, int n, int t) {
                this.k = k;
                this.n = n;
                this.t = t;
            }
        }
    }

    private final KEM kem;
    private final KDF kdf;
    private final AEAD aead;

    public HpkeAlgorithmIdentifier(KEM kem, KDF kdf, AEAD aead) {
        this.kem = checkNotNull(kem, "kem");
        this.kdf = checkNotNull(kdf, "kdf");
        this.aead = checkNotNull(aead, "aead");
    }

    /**
     * The Key Encapsulation Mechanism (KEM) identifier
     *
     * @return kem
     */
    public KEM getKem() {
        return kem;
    }

    /**
     * The Key Derivation Function (KDF) identifier
     *
     * @return kdf
     */
    public KDF getKdf() {
        return kdf;
    }

    /**
     * The Authenticated Encryption with Additional Data (AEAD) identifier
     *
     * @return aead
     */
    public AEAD getAead() {
        return aead;
    }
}
