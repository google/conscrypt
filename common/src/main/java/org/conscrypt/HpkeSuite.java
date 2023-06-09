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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Holds the KEM, KDF, and AEAD that are used and supported by {@link Hpke} defined on
 * RFC 9180.
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
   * {@link HpkeSuite} with the following algorithm scheme:
   * <li>
   *      <ul>KEM:  0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
   *      <ul>KDF:  0x0001: HKDF-SHA256</ul>
   *      <ul>AEAD: 0x0001: AES-128-GCM</ul>
   * </li>
   *
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-encapsulation-mechanism">KEMs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-derivation-functions-kd">KDFs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-authenticated-encryption-wi">AEAD</a>
   */
  public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM =
      new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM);

  /**
   * {@link HpkeSuite} with the following algorithm scheme:
   * <li>
   *      <ul>KEM:  0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
   *      <ul>KDF:  0x0001: HKDF-SHA256</ul>
   *      <ul>AEAD: 0x0002: AES-256-GCM</ul>
   * </li>
   *
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-encapsulation-mechanism">KEMs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-derivation-functions-kd">KDFs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-authenticated-encryption-wi">AEAD</a>
   */
  public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM =
      new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_256_GCM);

  /**
   * {@link HpkeSuite} with the following algorithm scheme:
   * <li>
   *      <ul>KEM  : 0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
   *      <ul>KDF  : 0x0001: HKDF-SHA256</ul>
   *      <ul>AEAD : 0x0003: ChaCha20Poly1305</ul>
   * </li>
   *
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-encapsulation-mechanism">KEMs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-key-derivation-functions-kd">KDFs</a>
   * @see <a
   * href="https://www.rfc-editor.org/rfc/rfc9180
   * .html#name-authenticated-encryption-wi">AEAD</a>
   */
  public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305 =
      new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.CHACHA20POLY1305);

  private final KEM mKem;
  private final KDF mKdf;
  private final AEAD mAead;

  private HpkeSuite(KEM Kem, KDF Kdf, AEAD Aead) {
    mKem = Kem;
    mKdf = Kdf;
    mAead = Aead;
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

  enum KEM {
    DHKEM_X25519_HKDF_SHA256(
        /* id= */ 32, /* encLength= */ 32, /* pkLength= */ 32, /* skLength= */ 32);

    private final int id;
    private final int encLength;
    private final int pkLength;
    private final int skLength;

    KEM(int id, int encLength, int pkLength, int skLength) {
      this.id = id;
      this.encLength = encLength;
      this.pkLength = pkLength;
      this.skLength = skLength;
    }

    /**
     * KEM id in its decimal representation
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
     * The length in bytes of an encoded public key for this KEM.
     *
     * @return public key size in bytes
     */
    int getPkLength() {
      return pkLength;
    }

    /**
     * The length in bytes of an encoded private key for this KEM.
     *
     * @return private key size in bytes
     */
    int getSkLength() {
      return skLength;
    }

    /**
     * Validates the enc size in bytes matches the {@link KEM} spec.
     *
     * @param enc encapsulated key produced by the kem
     * @see <a
     *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">expected
     *         enc size</a>
     */
    void validateEnc(byte[] enc) {
      Preconditions.checkNotNull(enc, "enc");
      final int expectedLength = this.getEncLength();
      if (enc.length != expectedLength) {
        throw new IllegalArgumentException(
            "Expected enc length of " + expectedLength + ", but was " + enc.length);
      }
    }

    /**
     * Validates the public key size in bytes to match the {@link KEM} public key spec.
     *
     * @param publicKey alias pk
     * @return key in its raw format
     * @see <a
     *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-algorithm-identifiers">expected
     *         pk size</a>
     */
    byte[] validateAndGetPublicKey(PublicKey publicKey) {
      Preconditions.checkNotNull(publicKey, "publicKey");
      if (!(publicKey instanceof OpenSSLX25519PublicKey)) {
        throw new IllegalArgumentException(
            "Public key algorithm " + publicKey.getAlgorithm() + " is not supported");
      }

      final byte[] key = ((OpenSSLX25519PublicKey) publicKey).getU();
      final int expectedLength = this.getPkLength();
      if (key.length != expectedLength) {
        throw new IllegalArgumentException("Expected public key length of " + expectedLength
            + ", but was " + key.length);
      }
      return key;
    }

    /**
     * Validates the private key size in bytes to match the {@link KEM} private key spec.
     *
     * @param privateKey alias sk
     * @return key in its raw format
     * @see <a
     *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-algorithm-identifiers">expected
     *         sk size</a>
     */
    byte[] validateAndGetPrivateKey(PrivateKey privateKey) {
      Preconditions.checkNotNull(privateKey, "privateKey");
      if (!(privateKey instanceof OpenSSLX25519PrivateKey)) {
        throw new IllegalArgumentException(
            "Private key algorithm " + privateKey.getAlgorithm() + " is not supported");
      }

      final byte[] key = ((OpenSSLX25519PrivateKey) privateKey).getU();
      final int expectedLength = this.getSkLength();
      if (key.length != expectedLength) {
        throw new IllegalArgumentException("Expected private key length of "
            + expectedLength + ", but was " + key.length);
      }
      return key;
    }
  }

  enum KDF {
    HKDF_SHA256(/* id= */ 1, /* hLength= */ 32);

    private final int id;
    private final int hLength;

    KDF(int id, int hLength) {
      this.id = id;
      this.hLength = hLength;
    }

    /**
     * KDF id in its decimal representation
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
    AES_128_GCM(/* id= */ 1),
    AES_256_GCM(/* id= */ 2),
    CHACHA20POLY1305(/* id= */ 3);

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
