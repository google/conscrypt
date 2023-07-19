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

import org.conscrypt.NativeRef.EVP_HPKE_CTX;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Hybrid Public Key Encryption (HPKE) APIs.
 * <p>
 * HPKE allows multiple cryptographic operations to be done based on a given setup transaction.
 * Therefore, the following APIs are stateful after setting up the transaction:
 * <ul>
 *     <li>{@link HpkeContext#open(byte[], byte[])} </li>
 *     <li>{@link HpkeContext#seal(byte[], byte[])}</li>
 *     <li>{@link HpkeContext#export(int, byte[])} </li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 */
public class HpkeContext {
  /** Represents the participant configured. */
  private enum SetupParticipant {
    NONE,
    SENDER,
    RECIPIENT
  }

  private final HpkeSuite mHpkeSuite;

  private HpkeContextHelper mContextHelper;
  private EVP_HPKE_CTX mCtx;
  private byte[] mEnc;

  private SetupParticipant mSetupParticipant;

  /**
   * Constructor defining the HPKE scheme to be used.
   *
   * @param hpkeSuite KEM, KDF, and AEAD scheme to be used
   */
  public HpkeContext(HpkeSuite hpkeSuite) {
    mHpkeSuite = hpkeSuite;
    mSetupParticipant = SetupParticipant.NONE;
    mContextHelper = new HpkeContextHelper();
  }

  /**
   *  Creates an instance of {@link HpkeContext} meant for testing only by supplying an additional
   *  {@link HpkeContextHelper}.
   */
  @Internal
  public static HpkeContext createForTestingOnly(HpkeSuite hpkeSuite, HpkeContextHelper contextHelper) {
    final HpkeContext hpkeContext = new HpkeContext(hpkeSuite);
    hpkeContext.mContextHelper = contextHelper;
    return hpkeContext;
  }

  /**
   * Hybrid Public Key Encryption (HPKE) decryption.
   * <p>
   * The API has a pre-requirement, an API call to set up[Mode]Recipient is needed so the API could
   * be properly initialized. This API is stateful.
   * <p><p>
   * Multiple messages decryption:<p>
   * If decrypting multiple messages that were encrypted using the same context in a sequence,
   * they must be decrypted in the same order as well. The API setup[Mode]Recipient must be called
   * just once before multiple calls to this API.
   * <p><p>
   * Single message decryption:<p>
   * If decryption a single message, the API setup[Mode]Recipient must be called
   * before every single message. Note: Calling setup[Mode][Sender|Recipient] resets the HPKE
   * context.
   *
   * @param ciphertext contains the encrypted plaintext.
   * @param aad        optional associated data.
   * @return plaintext.
   * @throws IllegalStateException if the API setup[Mode]Recipient hasn't been called or if an
   *                               issue happened while performing decryption operation (an issue
   *                               could occur most likely if the keys configured are not valid).
   */
  public byte[] open(byte[] ciphertext, byte[] aad) {
    if (mSetupParticipant != SetupParticipant.RECIPIENT) {
      throw new IllegalStateException("Setup recipient needs to be called before decryption");
    }

    Preconditions.checkNotNull(ciphertext, "ciphertext");
    try {
      return NativeCrypto.EVP_HPKE_CTX_open(mCtx, ciphertext, aad);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Error while decrypting with the keys provided during setup recipient", e);
    }
  }

  /**
   * Hybrid Public Key Encryption (HPKE) encryption.
   * <p>
   * The API has a pre-requirement, an API call to setup[Mode]Sender is needed so the API could be
   * properly initialized. This API is stateful.
   * <p><p>
   * Multiple messages encryption:<p>
   * If encrypting multiple messages that are expected to be decrypted in the same sequence as how
   * they are encrypted, the API setup[Mode]Sender must be called just once before multiple calls
   * to this API.
   * <p><p>
   * Single message encryption:<p>
   * If encrypting a single message, the API setup[Mode]Sender must be called
   * before every single message. Note: Calling setup[Mode][Sender|Recipient] resets the HPKE state.
   *
   * @param plaintext message that will be encrypted.
   * @param aad       optional associated data.
   * @return ciphertext.
   * @throws IllegalStateException if the API setup[Mode]Sender hasn't been called.
   */
  public byte[] seal(byte[] plaintext, byte[] aad) {
    if (mSetupParticipant != SetupParticipant.SENDER) {
      throw new IllegalStateException("Setup sender needs to be called before encryption");
    }

    Preconditions.checkNotNull(plaintext, "plaintext");
    return NativeCrypto.EVP_HPKE_CTX_seal(mCtx, plaintext, aad);
  }

  /**
   * Hybrid Public Key Encryption (HPKE) secret exports.
   * <p>
   * The API has a pre-requirement, an API call to setup[Mode][Sender|Recipient] is needed so the
   * API could be properly initialized.
   *
   * @param length          expected output length.
   * @param exporterContext optional exporter context.
   * @return exported value.
   * @throws IllegalArgumentException if the length is not valid based on the KDF specs.
   * @throws IllegalStateException if the API setup[Mode][Sender|Recipient] hasn't been called.
   */
  public byte[] export(int length, byte[] exporterContext) {
    if (mSetupParticipant == SetupParticipant.NONE) {
      throw new IllegalStateException(
          "Setup sender or recipient needs to be called before export");
    }

    mHpkeSuite.getKdf().validateExportLength(length);
    return NativeCrypto.EVP_HPKE_CTX_export(mCtx, exporterContext, length);
  }

  /**
   * Initializes the internal HPKE context for the recipient using BASE (0x00) mode. Call this API
   * before decrypting or exporting.
   *
   * @param enc        encapsulated key matching the KEM private key spec.
   * @param privateKey private key (secret key) matching the KEM private key spec.
   * @param info       optional application-supplied information.
   * @throws IllegalArgumentException if providing an invalid encapsulated key (enc) or a private
   *                                  key with invalid length not matching the KEM specs.
   * @throws IllegalStateException    if an issue is encountered while setting up the recipient
   *                                  (an issue could occur most likely if the keys configured are
   *                                  not valid).
   * @see <a
   *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-hybrid-public-key-encryptio">HPKE
   *         modes</a>
   */
  public void setupBaseRecipient(byte[] enc, PrivateKey privateKey, byte[] info) {
    mHpkeSuite.getKem().validateEncLength(enc);
    final byte[] sk = mHpkeSuite.getKem().validatePrivateKeyLengthAndGetRawKey(privateKey);

    mSetupParticipant = SetupParticipant.RECIPIENT;
    mEnc = enc;
    try {
      mCtx = (EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_recipient(
          mHpkeSuite.getKem().getId(), mHpkeSuite.getKdf().getId(),
          mHpkeSuite.getAead().getId(), sk, enc, info);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Error while setting up base recipient with the keys provided", e);
    }
  }

  /**
   * Initializes the internal HPKE context for the sender using BASE (0x00) mode. Call this API
   * before encrypting or exporting.
   *
   * @param publicKey public key matching the KEM public key spec.
   * @param info      optional application-supplied information.
   * @return encapsulated key.
   * @throws IllegalArgumentException if providing a public key with invalid length not matching
   *                                  the KEM specs.
   * @throws IllegalStateException    if an issue is encountered while setting up the sender
   *                                  (an issue could occur most likely if the keys configured are
   *                                  not valid).
   * @see <a
   *         href="https://www.rfc-editor.org/rfc/rfc9180.html#name-hybrid-public-key-encryptio">HPKE
   *         modes</a>
   */
  public byte[] setupBaseSender(PublicKey publicKey, byte[] info) {
    final byte[] pk = mHpkeSuite.getKem().validatePublicKeyLengthAndGetRawKey(publicKey);

    mSetupParticipant = SetupParticipant.SENDER;
    try {
      final Object[] result = mContextHelper.setupSenderBase(mHpkeSuite.getKem().getId(),
          mHpkeSuite.getKdf().getId(), mHpkeSuite.getAead().getId(), pk, info);
      mCtx = (EVP_HPKE_CTX) result[0];
      mEnc = (byte[]) result[1];
      return mEnc.clone();
    } catch (Exception e) {
      throw new IllegalStateException(
          "Error while setting up base sender with the keys provided", e);
    }
  }
}
