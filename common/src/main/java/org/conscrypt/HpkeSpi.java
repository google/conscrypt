package org.conscrypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * SPI for HPKE clients to communicate with implementations.  The client API can use any
 * implementation which implements this interface, by duck-typing if necessary.
 */
public interface HpkeSpi {
  byte[] DEFAULT_PSK = new byte[0];
  byte[] DEFAULT_PSK_ID = DEFAULT_PSK;

  /**
   * Initialises an HPKE sender SPI.
   *
   * @param recipientKey public key of the recipient
   * @param info application-supplied information, may be null or empty
   * @param senderKey private key of the sender, for symmetric auth modes only, else null
   * @param psk pre-shared key, for PSK auth modes only, else null
   * @param psk_id pre-shared key ID, for PSK auth modes only, else null
   * @throws InvalidKeyException if recipientKey is null or an unsupported key format
   * @throws UnsupportedOperationException if mode is not a supported HPKE mode
   * @throws IllegalStateException if this SPI has already been initialised
   */
  void engineInitSender(
          PublicKey recipientKey,
          byte[] info,
          PrivateKey senderKey,
          byte[] psk,
          byte[] psk_id)
          throws InvalidKeyException;

  /**
   * Initialises an HPKE sender SPI.
   *
   * @param recipientKey public key of the recipient
   * @param info application-supplied information, may be null or empty
   * @param senderKey private key of the sender, for symmetric auth modes only, else null
   * @param psk pre-shared key, for PSK auth modes only, else null
   * @param psk_id pre-shared key ID, for PSK auth modes only, else null
   * @param sKe optional random seed, should be null for all uses except for validation against
   *            known test vectors
   * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
   *            is an unsupported key format
   * @throws UnsupportedOperationException if mode is not a supported HPKE mode
   * @throws IllegalStateException if this SPI has already been initialised
   */
  void engineInitSenderForTesting(
          PublicKey recipientKey,
          byte[] info,
          PrivateKey senderKey,
          byte[] psk,
          byte[] psk_id,
          byte[] sKe)
          throws InvalidKeyException;

  /**
   * Initialises an HPKE recipient SPI.
   *
   * @param encapsulated encapsulated ephemeral key from a sender
   * @param recipientKey private key of the recipient
   * @param info application-supplied information, may be null or empty
   * @param senderKey public key of sender, for asymmetric auth modes only, else null
   * @param psk pre-shared key, for PSK auth modes only, else null
   * @param psk_id pre-shared key ID, for PSK auth modes only, else null
   * @throws InvalidKeyException if recipientKey is null or an unsupported key format or senderKey
   *         is an unsupported key format
   * @throws UnsupportedOperationException if mode is not a supported HPKE mode
   * @throws IllegalStateException if this SPI has already been initialised
   */
  void engineInitRecipient(
          byte[] encapsulated,
          PrivateKey recipientKey,
          byte[] info,
          PublicKey senderKey,
          byte[] psk,
          byte[] psk_id)
          throws InvalidKeyException;

  /**
   * Seals a message, using the internal key schedule maintained by an HPKE sender.
   *
   * @param plaintext the plaintext
   * @param aad optional associated data, may be null or empty
   * @return the ciphertext
   * @throws NullPointerException if the plaintext is null
   * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
   *         as a recipient
   */
  byte[] engineSeal(byte[] plaintext, byte[] aad);

  /**
   * Opens a message, using the internal key schedule maintained by an HPKE recipient.
   *
   * @param ciphertext the ciphertext
   * @param aad optional associated data, may be null or empty
   * @return the plaintext
   * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
   *         as a sender
   * @throws GeneralSecurityException on decryption failures
   */
  byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;

  /**
   * Exports secret key material from this SPI as described in RFC 9180.
   *
   * @param length  expected output length
   * @param context optional context string, may be null or empty
   * @return exported value
   * @throws IllegalArgumentException if the length is not valid for the KDF in use
   * @throws IllegalStateException if this SPI has not been initialised
   *
   */
  byte[] engineExport(int length, byte[] context);

  /**
   * Returns the encapsulated key material for an HPKE sender.
   *
   * @return the key material
   * @throws IllegalStateException if this SPI has not been initialised or if it was initialised
   *         as a recipient
   */
  byte[] getEncapsulated();
}
