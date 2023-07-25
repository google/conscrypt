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
import org.conscrypt.NativeRef.EVP_HPKE_CTX;

/**
 * Hybrid Public Key Encryption (HPKE) Recipient APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 */
public class HpkeContextRecipient {

  private final HpkeSuite hpkeSuite;
  private EVP_HPKE_CTX ctx;

  private HpkeContextRecipient(HpkeSuite hpkeSuite) {
    this.hpkeSuite = hpkeSuite;
  }

  /**
   * Initializes the internal HPKE context for the recipient using BASE (0x00) mode.
   *
   * @param enc        encapsulated key matching the KEM encapsulated key size
   * @param privateKey private key (secret key) matching the KEM private key size
   * @param info       optional application-supplied information
   * @throws IllegalArgumentException if providing an encapsulated key (enc) or private key that
   *                                  does not match the size expectation
   * @throws IllegalStateException    if an issue is encountered while setting up the recipient
   *                                  (an issue could occur most likely if the keys configured are
   *                                  not valid)
   */
  public static HpkeContextRecipient setupBase(
      HpkeSuite hpkeSuite, byte[] enc, PrivateKey privateKey, byte[] info) {
    hpkeSuite.getKem().validateEncLength(enc);
    final byte[] sk = hpkeSuite.getKem().validatePrivateKeyLengthAndGetRawKey(privateKey);
    try {
      final HpkeContextRecipient ctxRecipient = new HpkeContextRecipient(hpkeSuite);
      ctxRecipient.ctx = (EVP_HPKE_CTX) NativeCrypto.EVP_HPKE_CTX_setup_recipient(
          hpkeSuite.getKem().getId(), hpkeSuite.getKdf().getId(), hpkeSuite.getAead().getId(),
          sk, enc, info);
      return ctxRecipient;
    } catch (Exception e) {
      throw new IllegalStateException(
          "Error while setting up base recipient with the keys provided", e);
    }
  }

  /**
   * Hybrid Public Key Encryption (HPKE) decryption.
   * <p>
   * Note: This API is stateful.
   * <p><p>
   * Multiple message decryption:<p>
   * If decrypting multiple messages that were encrypted in a sequence using the same context,
   * they must be decrypted in the same order as well. The method setup[Mode]Recipient must be
   * called just once before multiple calls to this API are made.
   * <p><p>
   * Single message decryption:<p>
   * If decrypting a single message, the method setup[Mode]Recipient must be called before each
   * message. Calling setup[Mode]Recipient creates a new HPKE context.
   *
   * @param ciphertext contains the encrypted plaintext
   * @param aad        optional associated data
   * @return plaintext
   * @throws IllegalStateException if an issue is encountered while decrypting (an issue could occur
   *                               most likely if the keys configured are not valid)
   */
  public byte[] open(byte[] ciphertext, byte[] aad) {
    Preconditions.checkNotNull(ciphertext, "ciphertext");
    try {
      return NativeCrypto.EVP_HPKE_CTX_open(ctx, ciphertext, aad);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Error while decrypting with the keys provided during setup recipient", e);
    }
  }

  /**
   * Hybrid Public Key Encryption (HPKE) secret export.
   *
   * @param length          expected output length
   * @param exporterContext optional exporter context
   * @return exported value
   * @throws IllegalArgumentException if the length is not valid based on the KDF spec
   */
  public byte[] export(int length, byte[] exporterContext) {
    hpkeSuite.getKdf().validateExportLength(length);
    return NativeCrypto.EVP_HPKE_CTX_export(ctx, exporterContext, length);
  }
}
