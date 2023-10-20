package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;

/**
 * SPI for HPKE clients to communicate with implementations.  The client API can use any
 * implementation which implements this interface, by duck-typing if necessary.
 */
public interface HpkeSpi {

  /**
   * Initialises an HPKE sender SPI.
   *
   * @param mode HPKE mode to use
   * @param publicKey public key of the recipient
   * @param info application-supplied information, may be null or empty
   * @param sKe optional random seed, should be null for all uses except for validation against
   *            known test vectors
   * @throws InvalidKeyException if publicKey is null or an unsupported key format
   * @throws UnsupportedOperationException if mode is not a supported HPKE mode
   * @throws IllegalStateException if this SPI has already been initialised
   */
  void engineInitSender(int mode, PublicKey publicKey, byte[] info, byte[] sKe)
          throws InvalidKeyException;

  /**
   * Initialises an HPKE recipient SPI.
   *
   * @param mode HPKE mode to use
   * @param enc encapsulated ephemeral key from a sender
   * @param privateKey private key of the recipient
   * @param info application-supplied information, may be null or empty
   * @throws InvalidKeyException if privateKey is null or an unsupported key format
   * @throws UnsupportedOperationException if mode is not a supported HPKE mode
   * @throws IllegalStateException if this SPI has already been initialised
   */
  void engineInitRecipient(int mode, byte[] enc, PrivateKey privateKey, byte[] info)
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
   * @throws javax.crypto.BadPaddingException on decryption failures (XXX rework this but it's what
   *        Cipher does!)
   */
  byte[] engineOpen(byte[] ciphertext, byte[] aad) throws BadPaddingException;

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
