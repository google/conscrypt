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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Hybrid Public Key Encryption (HPKE) recipient APIs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#hpke-export">HPKE RFC 9180</a>
 *
 * Recipient subclass of HpkeContext.  See base class for details.
 */
public class HpkeContextRecipient extends HpkeContext {
    private HpkeContextRecipient(HpkeSpi spi) {
        super(spi);
    }

    /**
     * Opens a message, using the internal key schedule maintained by this HpkeContextRecipient.
     *
     * @param ciphertext the ciphertext
     * @param aad optional associated data, may be null or empty
     * @return the plaintext
     * @throws IllegalStateException if this HpkeContextRecipient has not been initialised
     * @throws GeneralSecurityException on decryption failures
     */
    public byte[] open(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
        return spi.engineOpen(ciphertext, aad);
    }

    /**
     * Returns an uninitialised HpkeContextRecipient.
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     */
    public static HpkeContextRecipient getInstance(String suite) throws NoSuchAlgorithmException {
        return new HpkeContextRecipient(findSpi(suite));
    }

    /**
     * Returns an uninitialised HpkeContextRecipient from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param providerName the name of the Provider to use
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if providerName is null or no such Provider exists
     */
    public static HpkeContextRecipient getInstance(String suite, String providerName)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextRecipient(findSpi(suite, providerName));
    }

    /**
     * Returns an uninitialised HpkeContextRecipient from a specific {@link Provider}
     *
     * @param suite the HPKE suite to use.  @see {@link HpkeSuite} for details.
     * @param provider the Provider to use
     * @return an uninitialised HpkeContextRecipient for the requested suite
     * @throws NoSuchAlgorithmException if no implementation could be found
     * @throws NoSuchProviderException if providerName is null or no such Provider exists
     */
    public static HpkeContextRecipient getInstance(String suite, Provider provider)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        return new HpkeContextRecipient(findSpi(suite, provider));
    }

    /**
     * Initialises this HpkeContextRecipient in BASE mode, i.e. no sender authentication.
     *
     * @param encapsulated encapsulated ephemeral key from an {@link HpkeContextSender}
     * @param recipientKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextRecipient has already been initialised
     */
    public void init(byte[] encapsulated, PrivateKey recipientKey, byte[] info)
            throws InvalidKeyException {
        spi.engineInitRecipient(encapsulated, recipientKey, info, null,
                HpkeSpi.DEFAULT_PSK, HpkeSpi.DEFAULT_PSK_ID);
    }

    /**
     * Initialises this HpkeContextRecipient in AUTH mode, i.e. messages are authenticated using
     * the sender's public key.
     *
     * @param encapsulated encapsulated ephemeral key from an {@link HpkeContextSender}
     * @param recipientKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param senderKey the public key of the sender
     * @throws InvalidKeyException if either recipientKey or senderKey are null
     *         or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextRecipient has already been initialised
     */
    public void init(byte[] encapsulated, PrivateKey recipientKey, byte[] info, PublicKey senderKey)
        throws InvalidKeyException {
        if (senderKey == null) {
            throw new InvalidKeyException("null sender key");
        }
        // Remaining argument checks are performed by the SPI
        spi.engineInitRecipient(encapsulated, recipientKey, info, senderKey,
                HpkeSpi.DEFAULT_PSK, HpkeSpi.DEFAULT_PSK_ID);
    }

    /**
     * Initialises this HpkeContextRecipient in PSK_AUTH mode, i.e. messages are authenticated using
     * a pre-shared secret key.
     *
     * @param encapsulated encapsulated ephemeral key from an {@link HpkeContextSender}
     * @param recipientKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param psk the a pre-shared secret key
     * @param psk_id the id of the pre-shared secret key
     * @throws NullPointerException if psk or psk_id are null
     * @throws InvalidKeyException if recipientKey is null or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextRecipient has already been initialised
     */
    public void init(byte[] encapsulated, PrivateKey recipientKey, byte[] info,
            byte[] psk, byte[] psk_id) throws InvalidKeyException {
        spi.engineInitRecipient(encapsulated, recipientKey, info, null, psk, psk_id);
    }

    /**
     * Initialises this HpkeContextRecipient in PSK_AUTH mode, i.e. messages are authenticated using
     * both the sender's public key and a pre-shared secret key.
     *
     * @param encapsulated encapsulated ephemeral key from an {@link HpkeContextSender}
     * @param recipientKey private key of the recipient
     * @param info application-supplied information, may be null or empty
     * @param senderKey the public key of the sender
     * @param psk the a pre-shared secret key
     * @param psk_id the id of the pre-shared secret key
     * @throws NullPointerException if psk or psk_id are null
     * @throws InvalidKeyException if either recipientKey or senderKey are null
     *         or an unsupported key format
     * @throws UnsupportedOperationException if mode is not a supported HPKE mode
     * @throws IllegalStateException if this HpkeContextRecipient has already been initialised
     */
    public void init(byte[] encapsulated, PrivateKey recipientKey, byte[] info, PublicKey senderKey,
            byte[] psk, byte[] psk_id) throws InvalidKeyException {
        if (senderKey == null) {
            throw new InvalidKeyException("null sender key");
        }
        // Remaining argument checks are performed by the SPI
        spi.engineInitRecipient(encapsulated, recipientKey, info, senderKey, psk, psk_id);
    }
}
